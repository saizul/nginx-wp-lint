from __future__ import annotations

import io
import json
import os

import pytest

from nginx_wp_lint.cli import EXIT_FINDINGS, EXIT_OK, EXIT_PARSE, EXIT_USAGE, main

from .conftest import FIXTURES

BAD = FIXTURES / "bad"


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    code = main([*argv, "--no-config"] if "--config" not in argv and "-c" not in argv
                else list(argv), stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


def test_clean_config_exit_zero():
    code, out, _ = run(str(FIXTURES / "good"))
    assert code == EXIT_OK
    assert out == "no problems in 8 files\n"


def test_findings_exit_one():
    code, out, _ = run(str(BAD / "naive-wordpress.conf"))
    assert code == EXIT_FINDINGS
    assert "NWL007" in out


def test_fail_on_threshold():
    path = str(BAD / "static-only.conf")
    assert run(path)[0] == EXIT_FINDINGS  # low findings, default fail_on low
    assert run(path, "--fail-on", "medium")[0] == EXIT_OK
    assert run(str(BAD / "naive-wordpress.conf"), "--fail-on", "never")[0] == EXIT_OK


def test_parse_error_exit_three():
    code, out, _ = run(str(BAD / "syntax-error.conf"))
    assert code == EXIT_PARSE
    assert "NWL000" in out


def test_formats_and_output_file(tmp_path):
    target = tmp_path / "out.sarif"
    code, out, err = run(str(BAD / "naive-wordpress.conf"), "-f", "sarif", "-o", str(target))
    assert code == EXIT_FINDINGS
    assert out == ""
    assert "wrote" in err
    assert json.loads(target.read_text())["version"] == "2.1.0"
    code, out, _ = run(str(BAD / "naive-wordpress.conf"), "-f", "json")
    assert json.loads(out)["summary"]["problems"] > 5
    code, out, _ = run(str(BAD / "naive-wordpress.conf"), "-f", "github")
    assert out.startswith("::")


def test_disable_enable_only_severity():
    path = str(BAD / "naive-wordpress.conf")
    _, out, _ = run(path, "--enable-only", "NWL002,NWL007", "-q")
    assert {line.split()[2] for line in out.splitlines()} == {"NWL002", "NWL007"}
    _, out, _ = run(path, "--enable-only", "NWL002", "--severity", "NWL002=high", "-q")
    assert " high NWL002 " in out
    _, out, _ = run(path, "--disable", "NWL002", "--disable", "php-in-uploads", "-q")
    assert "NWL002" not in out and "NWL007" not in out
    _, out, _ = run(path, "--min-severity", "high", "-q")
    assert all(" high " in line for line in out.splitlines())


def test_bad_arguments():
    assert run(str(BAD / "naive-wordpress.conf"), "--disable", "NWL999")[0] == EXIT_USAGE
    assert run(str(BAD / "naive-wordpress.conf"), "--severity", "NWL001")[0] == EXIT_USAGE
    code, _, err = run("/does/not/exist.conf")
    assert code == EXIT_USAGE and "no such file" in err
    with pytest.raises(SystemExit) as info:
        main(["--format", "xml"])
    assert info.value.code == 2


def test_config_file_option():
    code, out, _ = run(str(BAD / "static-only.conf"), "-c",
                       str(FIXTURES / "configs" / "basic.yml"))
    assert code == EXIT_OK  # fail_on high
    assert "NWL016" not in out


def test_config_discovery(tmp_path, monkeypatch):
    (tmp_path / ".nginx-wp-lint.toml").write_text('disable = ["NWL002"]\n')
    monkeypatch.chdir(tmp_path)
    out = io.StringIO()
    main([str(BAD / "naive-wordpress.conf"), "-q"], stdout=out, stderr=io.StringIO())
    assert "NWL002" not in out.getvalue()
    out = io.StringIO()
    main([str(BAD / "naive-wordpress.conf"), "-q", "--no-config"], stdout=out,
         stderr=io.StringIO())
    assert "NWL002" in out.getvalue()


def test_list_rules_and_explain():
    code, out, _ = run("--list-rules")
    assert code == EXIT_OK and "NWL007  high" in out
    code, out, _ = run("--explain", "php-in-uploads")
    assert code == EXIT_OK and out.startswith("NWL007 php-in-uploads")
    assert "Fix:" in out
    assert run("--explain", "nope")[0] == EXIT_USAGE


def test_print_tree():
    code, out, _ = run("--print-tree", str(FIXTURES / "includes" / "conf"))
    assert code == EXIT_OK
    assert "include missing-file.conf;  -> NOT FOUND" in out
    assert "autoindex on;" in out


def test_base_option(tmp_path):
    _, out, _ = run(str(BAD / "naive-wordpress.conf"), "--base", str(BAD), "-q")
    assert out.splitlines()[0].startswith("naive-wordpress.conf:")


def test_prefix_and_no_includes():
    site = FIXTURES / "prefix" / "etc" / "nginx" / "sites-enabled" / "site.conf"
    _, out, _ = run(str(site), "--enable-only", "NWL012,NWL090", "-q")
    assert out == ""
    _, out, _ = run(str(site), "--enable-only", "NWL012", "--no-includes", "-q")
    assert "NWL012" in out


def test_default_path_is_current_dir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "site.conf").write_text("server { listen 80; autoindex on; }\n")
    if os.path.isdir("/etc/nginx"):
        pytest.skip("/etc/nginx exists on this machine")
    out = io.StringIO()
    code = main(["--no-config", "-q"], stdout=out, stderr=io.StringIO())
    assert code == EXIT_FINDINGS and "NWL002" in out.getvalue()


def test_version(capsys):
    with pytest.raises(SystemExit):
        main(["--version"])
    assert "nginx-wp-lint 0.1.0" in capsys.readouterr().out
