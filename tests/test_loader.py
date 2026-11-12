from __future__ import annotations

import os

from nginx_wp_lint.loader import default_prefixes, load


def test_glob_includes_and_nesting(fixtures):
    cfg = load(fixtures / "includes" / "conf" / "nginx.conf")
    names = [d.name for d in cfg.root.walk()]
    assert names.count("server") == 2
    autoindex = next(d for d in cfg.root.walk() if d.name == "autoindex")
    # Spliced inside the location that included it, with its own file and line.
    assert autoindex.parent.name == "location"
    assert autoindex.file.endswith(os.path.join("snippets", "inner.conf"))
    assert autoindex.line == 2
    assert autoindex.via_include is not None and autoindex.via_include.name == "include"


def test_missing_include_and_empty_glob(fixtures):
    cfg = load(fixtures / "includes" / "conf" / "nginx.conf")
    missing = [d.arg(0) for d in cfg.missing_includes]
    assert "missing-file.conf" in missing
    assert "optional/*.conf" not in missing  # an empty glob is fine for nginx
    glob_inc = next(d for d in cfg.root.walk() if d.name == "include"
                    and d.arg(0) == "optional/*.conf")
    assert glob_inc.include_resolved is True and glob_inc.included_files == []


def test_include_cycle_is_an_error(fixtures):
    cfg = load(fixtures / "includes" / "conf" / "nginx.conf")
    assert any("include cycle" in e.message for e in cfg.errors)


def test_site_file_resolves_against_parent_dir(fixtures):
    site = fixtures / "prefix" / "etc" / "nginx" / "sites-enabled" / "site.conf"
    cfg = load(site)
    assert not cfg.missing_includes
    assert any(d.name == "add_header" for d in cfg.root.walk())


def test_explicit_prefix(fixtures, tmp_path):
    conf = tmp_path / "x.conf"
    conf.write_text("server { include snippets/headers.conf; }\n", encoding="utf-8")
    cfg = load(conf, prefix=str(fixtures / "prefix" / "etc" / "nginx"))
    assert not cfg.missing_includes


def test_no_includes(fixtures):
    cfg = load(fixtures / "includes" / "conf" / "nginx.conf", follow_includes=False)
    assert not any(d.name == "server" for d in cfg.root.walk())


def test_unreadable_and_broken_files(tmp_path):
    cfg = load(tmp_path / "nope.conf")
    assert cfg.errors and "cannot read" in cfg.errors[0].message
    bad = tmp_path / "bad.conf"
    bad.write_text("server {\n", encoding="utf-8")
    assert not load(bad).ok


def test_parse_error_in_included_file(tmp_path):
    (tmp_path / "inc.conf").write_text("listen 80\n", encoding="utf-8")
    main = tmp_path / "nginx.conf"
    main.write_text("http { include inc.conf; }\n", encoding="utf-8")
    cfg = load(main)
    assert cfg.errors[0].file.endswith("inc.conf")


def test_default_prefixes(tmp_path):
    site = tmp_path / "sites-enabled" / "a.conf"
    prefixes = default_prefixes(str(site), None)
    assert prefixes == [str(tmp_path / "sites-enabled"), str(tmp_path)]
    assert default_prefixes(str(site), "/etc/nginx")[0] == "/etc/nginx"
