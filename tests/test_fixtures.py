"""Every fixture file with the exact set of rules it must trigger."""

from __future__ import annotations

import os

import pytest

from nginx_wp_lint.config import Settings
from nginx_wp_lint.linter import lint_paths

from .conftest import FIXTURES

BAD = FIXTURES / "bad"

COMMON_FRAGMENT = {"NWL001", "NWL012", "NWL013", "NWL014", "NWL016", "NWL020"}
WP_EXPOSED = {"NWL003", "NWL004", "NWL005", "NWL006", "NWL007"}

EXPECTED = {
    "naive-wordpress.conf": COMMON_FRAGMENT | WP_EXPOSED | {
        "NWL002", "NWL022", "NWL051", "NWL052", "NWL060"},
    "tls-weak.conf": {"NWL001", "NWL003", "NWL004", "NWL005", "NWL006", "NWL007", "NWL010",
                      "NWL011", "NWL012", "NWL013", "NWL014", "NWL016", "NWL017", "NWL020",
                      "NWL022", "NWL040", "NWL041", "NWL042", "NWL043", "NWL046", "NWL060"},
    "no-redirect.conf": COMMON_FRAGMENT | {"NWL003", "NWL004", "NWL008", "NWL010", "NWL022",
                                           "NWL044", "NWL046"},
    "header-inheritance.conf": {"NWL001", "NWL003", "NWL004", "NWL008", "NWL015", "NWL017",
                                "NWL020", "NWL022", "NWL046"},
    "fastcgi-cache.conf": {"NWL003", "NWL004", "NWL005", "NWL006", "NWL007", "NWL012",
                           "NWL013", "NWL014", "NWL016", "NWL030", "NWL031", "NWL032",
                           "NWL033", "NWL061"},
    "pitfalls.conf": COMMON_FRAGMENT | {"NWL005", "NWL006", "NWL007", "NWL022", "NWL051",
                                        "NWL060", "NWL070", "NWL071", "NWL072", "NWL073",
                                        "NWL074", "NWL075"},
    "dotfiles-partial.conf": COMMON_FRAGMENT | {"NWL004", "NWL005", "NWL006", "NWL007",
                                                "NWL009", "NWL022", "NWL060"},
    "static-only.conf": {"NWL001", "NWL012", "NWL013", "NWL014", "NWL016", "NWL020"},
    "php-source.conf": COMMON_FRAGMENT | {"NWL003", "NWL004", "NWL008", "NWL022"},
    "if-block-guard.conf": COMMON_FRAGMENT | {"NWL004", "NWL005", "NWL007", "NWL022",
                                              "NWL060"},
    "lua-and-quotes.conf": COMMON_FRAGMENT | WP_EXPOSED | {"NWL022", "NWL050", "NWL051",
                                                           "NWL052", "NWL060"},
    "syntax-error.conf": {"NWL000"},
    "unbalanced.conf": {"NWL000"},
    "suppressed.conf": {"NWL001", "NWL003", "NWL004", "NWL005", "NWL007", "NWL012", "NWL014",
                        "NWL016", "NWL020", "NWL022"},
}


def test_every_bad_fixture_is_listed():
    assert {p.name for p in BAD.glob("*.conf")} == set(EXPECTED)


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_fixture_rules(name):
    result = lint_paths([str(BAD / name)], Settings())
    assert {f.rule_id for f in result.findings} == EXPECTED[name]


def test_good_config_is_clean():
    result = lint_paths([str(FIXTURES / "good")], Settings())
    assert result.findings == [], [f"{f.rule_id} {f.message}" for f in result.findings]
    assert len(result.files) == 8
    assert len(result.roots) == 1 and result.roots[0].endswith("nginx.conf")


def test_suppressed_count():
    result = lint_paths([str(BAD / "suppressed.conf")], Settings())
    # NWL013 (file), NWL006 + NWL060 (block), NWL002 (same line)
    assert result.suppressed == 4


def test_includes_fixture():
    result = lint_paths([str(FIXTURES / "includes" / "conf")], Settings())
    ids = {f.rule_id for f in result.findings}
    assert "NWL000" in ids  # include cycle
    assert "NWL002" in ids  # autoindex from the snippet included in a location
    autoindex = next(f for f in result.findings if f.rule_id == "NWL002")
    assert autoindex.file.endswith("inner.conf") and autoindex.line == 2
    assert any(f.rule_id == "NWL090" and "missing-file.conf" in f.message
               for f in result.findings)


def test_directory_without_nginx_conf_lints_each_file():
    result = lint_paths([str(BAD)], Settings(enable_only={"NWL002"}))
    assert len(result.roots) == len(EXPECTED)
    assert result.parse_errors == 2


def test_included_files_are_not_linted_twice():
    good = FIXTURES / "good"
    result = lint_paths([str(good / "nginx.conf"),
                         str(good / "sites-enabled" / "example.com.conf")], Settings())
    assert len(result.roots) == 1


def test_directory_scan_picks_debian_site_files(tmp_path):
    sites = tmp_path / "sites-enabled"
    sites.mkdir()
    (sites / "default").write_text("server { listen 80; autoindex on; }\n")
    (sites / "example.com").write_text("server { listen 80; autoindex on; }\n")
    (sites / "example.com~").write_text("server { autoindex on; }\n")
    (sites / ".hidden").write_text("server { autoindex on; }\n")
    (tmp_path / "notes.txt").write_text("not nginx\n")
    result = lint_paths([str(tmp_path)], Settings(enable_only={"NWL002"}))
    assert sorted(os.path.basename(r) for r in result.roots) == ["default", "example.com"]
