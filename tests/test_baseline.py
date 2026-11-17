from __future__ import annotations

import io
import json

import pytest

from nginx_wp_lint import baseline
from nginx_wp_lint.cli import EXIT_FINDINGS, EXIT_OK, EXIT_PARSE, EXIT_USAGE, main
from nginx_wp_lint.linter import lint_paths
from nginx_wp_lint.rules import Finding, Severity

SITE = """\
server {
    listen 80;
    server_name static.example.com;
    root /var/www/static;
    location / {
        try_files $uri $uri/ =404;
    }
}
"""


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    code = main([*argv, "--no-config"] if "--config" not in argv else list(argv),
                stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


@pytest.fixture
def site(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    path = tmp_path / "site.conf"
    path.write_text(SITE, encoding="utf-8")
    return path


def finding(**kw) -> Finding:
    data = {"rule_id": "NWL012", "rule_name": "x", "severity": Severity.LOW,
            "message": "X-Content-Type-Options header is not set", "file": "site.conf",
            "line": 2, "context": "static.example.com:80"}
    data.update(kw)
    return Finding(**data)


def test_write_then_check_passes(site):
    code, _, err = run("site.conf", "--write-baseline", "baseline.json")
    assert code == EXIT_OK
    assert "wrote baseline baseline.json" in err
    data = json.loads((site.parent / "baseline.json").read_text())
    assert data["tool"] == "nginx-wp-lint"
    assert data["format"] == baseline.FORMAT_VERSION
    assert len(data["entries"]) == 6
    assert {e["file"] for e in data["entries"]} == {"site.conf"}

    code, out, err = run("site.conf", "--baseline", "baseline.json")
    assert code == EXIT_OK
    assert out == "no problems in 1 file, 6 baselined\n"
    assert "no longer match" not in err


def test_baseline_survives_unrelated_line_shifts(site):
    run("site.conf", "--write-baseline", "baseline.json")
    site.write_text("# a comment\n\n# another\n" + SITE, encoding="utf-8")
    code, out, _ = run("site.conf", "--baseline", "baseline.json")
    assert code == EXIT_OK, out
    assert "6 baselined" in out


def test_new_problem_is_reported(site):
    run("site.conf", "--write-baseline", "baseline.json")
    site.write_text(SITE.replace("    root", "    autoindex on;\n    root"), encoding="utf-8")
    code, out, _ = run("site.conf", "--baseline", "baseline.json")
    assert code == EXIT_FINDINGS
    lines = [ln for ln in out.splitlines() if ln.startswith("site.conf:")]
    assert len(lines) == 1
    assert "autoindex" in lines[0]
    assert "6 baselined" in out


def test_fixed_problem_is_stale(site):
    run("site.conf", "--write-baseline", "baseline.json")
    site.write_text(SITE.replace(
        "    root", "    add_header X-Content-Type-Options nosniff always;\n    root"),
        encoding="utf-8")
    code, out, err = run("site.conf", "--baseline", "baseline.json")
    assert code == EXIT_OK
    assert "5 baselined" in out
    assert "1 baseline entry no longer match" in err
    assert "--write-baseline baseline.json" in err

    code, out, _ = run("site.conf", "--baseline", "baseline.json", "-f", "json")
    summary = json.loads(out)["summary"]
    assert summary["baselined"] == 5
    assert summary["baseline_stale"] == 1


def test_quiet_hides_stale_note(site):
    run("site.conf", "--write-baseline", "baseline.json")
    site.write_text(SITE.replace("    root", "    server_tokens off;\n    root"),
                    encoding="utf-8")
    _, _, err = run("site.conf", "--baseline", "baseline.json", "-q")
    assert err == ""


def test_editing_the_flagged_line_invalidates_entry(site):
    run("site.conf", "--write-baseline", "baseline.json")
    # The server-level findings point at the `server {` line.
    site.write_text(SITE.replace("server {", "server  { # edited"), encoding="utf-8")
    code, out, _ = run("site.conf", "--baseline", "baseline.json")
    assert code == EXIT_FINDINGS
    assert "6 baselined" not in out


def test_missing_and_invalid_baseline_are_usage_errors(site):
    code, _, err = run("site.conf", "--baseline", "nope.json")
    assert code == EXIT_USAGE
    assert "baseline file nope.json not found" in err

    (site.parent / "bad.json").write_text("{not json", encoding="utf-8")
    code, _, err = run("site.conf", "--baseline", "bad.json")
    assert code == EXIT_USAGE
    assert "invalid JSON" in err

    (site.parent / "other.json").write_text('{"format": 99, "entries": []}', encoding="utf-8")
    code, _, err = run("site.conf", "--baseline", "other.json")
    assert code == EXIT_USAGE
    assert "unsupported baseline format 99" in err


def test_write_baseline_to_unwritable_path(site):
    code, _, err = run("site.conf", "--write-baseline", "missing-dir/baseline.json")
    assert code == EXIT_USAGE
    assert "cannot write baseline" in err


def test_write_baseline_with_parse_errors(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "broken.conf").write_text("server {\n    listen 80;\n", encoding="utf-8")
    code, _, err = run("broken.conf", "--write-baseline", "baseline.json")
    assert code == EXIT_PARSE
    assert "parse errors are recorded" in err
    assert (tmp_path / "baseline.json").is_file()


def test_config_file_baseline_is_relative_to_config(tmp_path, monkeypatch):
    conf_dir = tmp_path / "ci"
    conf_dir.mkdir()
    (tmp_path / "site.conf").write_text(SITE, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    assert run("site.conf", "--write-baseline", "ci/baseline.json")[0] == EXIT_OK
    (conf_dir / "lint.toml").write_text('baseline = "baseline.json"\n', encoding="utf-8")

    code, out, _ = run("site.conf", "--config", "ci/lint.toml")
    assert code == EXIT_OK
    assert "6 baselined" in out

    code, out, _ = run("site.conf", "--config", "ci/lint.toml", "--no-baseline")
    assert code == EXIT_FINDINGS
    assert "baselined" not in out


def test_config_rejects_non_string_baseline(tmp_path):
    from nginx_wp_lint.config import ConfigError, Settings, apply_dict

    with pytest.raises(ConfigError, match="baseline must be a file path"):
        apply_dict(Settings(), {"baseline": 3})


def test_duplicate_fingerprints_are_counted():
    a, b = finding(), finding()
    accepted = baseline.Baseline.from_findings([a])
    match = baseline.apply([a, b], accepted)
    assert match.matched == 1
    assert match.new == [b]
    assert match.stale == []


def test_fingerprint_ignores_line_numbers_without_source():
    # The file does not exist, so only rule/path/context/message count.
    assert baseline.fingerprint(finding(line=2)) == baseline.fingerprint(finding(line=40))
    assert baseline.fingerprint(finding()) != baseline.fingerprint(finding(rule_id="NWL013"))
    assert baseline.fingerprint(finding()) != baseline.fingerprint(finding(context="other:80"))


def test_fingerprint_normalises_whitespace(tmp_path):
    conf = tmp_path / "one.conf"
    conf.write_text("x\nserver {\n", encoding="utf-8")
    before = baseline.fingerprint(finding(file=str(conf)), base=str(tmp_path))
    conf.write_text("x\n   server\t{   \n", encoding="utf-8")
    after = baseline.fingerprint(finding(file=str(conf)), base=str(tmp_path))
    assert before == after
    conf.write_text("x\nserver { # changed\n", encoding="utf-8")
    assert baseline.fingerprint(finding(file=str(conf)), base=str(tmp_path)) != before


def test_parse_rejects_bad_entries():
    with pytest.raises(baseline.BaselineError, match="no 'entries' list"):
        baseline.parse("[]")
    with pytest.raises(baseline.BaselineError, match="entry 0 has no fingerprint"):
        baseline.parse('{"entries": [{"rule": "NWL001"}]}')
    parsed = baseline.parse('{"entries": [{"fingerprint": "abc", "line": "x"}]}')
    assert parsed.entries[0].line == 0


def test_round_trip_is_stable(site):
    result = lint_paths(["site.conf"])
    first = baseline.Baseline.from_findings(result.findings).to_json()
    again = baseline.parse(first)
    assert baseline.Baseline(again.entries).to_json() == first
    assert baseline.apply(result.findings, again).new == []
