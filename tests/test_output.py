from __future__ import annotations

import json

import pytest

from nginx_wp_lint.linter import lint_paths
from nginx_wp_lint.output import FORMATS, render
from nginx_wp_lint.output.paths import display_path
from nginx_wp_lint.rules import ALL_RULES

from .conftest import FIXTURES


@pytest.fixture
def result():
    return lint_paths([str(FIXTURES / "bad" / "naive-wordpress.conf"),
                       str(FIXTURES / "bad" / "syntax-error.conf")])


def test_text(result):
    out = render(result, "text")
    assert "naive-wordpress.conf:7:5: medium NWL002 autoindex-on:" in out
    assert "    hint: " in out
    assert out.rstrip().splitlines()[-1].startswith(f"{len(result.findings)} problems (")
    quiet = render(result, "text", quiet=True)
    assert "hint:" not in quiet and "problems" not in quiet


def test_text_clean():
    clean = lint_paths([str(FIXTURES / "good")])
    assert render(clean, "text") == "no problems in 8 files\n"


def test_json(result):
    data = json.loads(render(result, "json"))
    assert data["tool"]["name"] == "nginx-wp-lint"
    assert data["summary"]["problems"] == len(result.findings)
    assert data["summary"]["parse_errors"] == 1
    first = data["findings"][0]
    assert set(first) >= {"rule", "name", "severity", "message", "file", "line", "column",
                          "hint"}


def test_sarif_structure(result):
    doc = json.loads(render(result, "sarif"))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "nginx-wp-lint"
    assert [r["id"] for r in driver["rules"]] == [r.id for r in ALL_RULES]
    for rule in driver["rules"]:
        assert rule["shortDescription"]["text"]
        assert rule["defaultConfiguration"]["level"] in ("error", "warning", "note")
        assert float(rule["properties"]["security-severity"]) > 0
    assert run["invocations"][0]["executionSuccessful"] is False
    res = run["results"]
    assert len(res) == len(result.findings)
    for item in res:
        assert driver["rules"][item["ruleIndex"]]["id"] == item["ruleId"]
        loc = item["locations"][0]["physicalLocation"]
        assert not loc["artifactLocation"]["uri"].startswith("/")
        assert "\\" not in loc["artifactLocation"]["uri"]
        assert loc["region"]["startLine"] >= 1
        assert item["partialFingerprints"]


def test_sarif_levels(result):
    doc = json.loads(render(result, "sarif"))
    levels = {r["ruleId"]: r["level"] for r in doc["runs"][0]["results"]}
    assert levels["NWL007"] == "error"
    assert levels["NWL002"] == "warning"
    assert levels["NWL001"] == "note"


def test_github_annotations(result):
    out = render(result, "github")
    lines = out.splitlines()
    assert len(lines) == len(result.findings)
    assert any(line.startswith("::error file=") for line in lines)
    assert all("%0A" in line for line in lines if "hint" not in line)


def test_github_escaping():
    from nginx_wp_lint.output.github import _escape_data, _escape_prop

    assert _escape_data("a%b\nc") == "a%25b%0Ac"
    assert _escape_prop("a:b,c") == "a%3Ab%2Cc"


def test_unknown_format(result):
    assert set(FORMATS) == {"text", "json", "sarif", "github"}
    with pytest.raises(ValueError):
        render(result, "xml")


def test_display_path(tmp_path):
    assert display_path("<string>") == "<string>"
    inside = tmp_path / "a" / "b.conf"
    assert display_path(str(inside), base=str(tmp_path)) == "a/b.conf"
    assert display_path("/etc/nginx/nginx.conf", base=str(tmp_path)).startswith("/")
