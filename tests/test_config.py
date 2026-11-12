from __future__ import annotations

import pytest

from nginx_wp_lint.config import (
    ConfigError,
    Settings,
    apply_dict,
    discover,
    is_excluded,
    load_file,
)
from nginx_wp_lint.linter import lint_paths
from nginx_wp_lint.rules import Severity

from .conftest import FIXTURES, lint

CONFIGS = FIXTURES / "configs"


def test_toml_config():
    s = load_file(CONFIGS / "strict.toml")
    assert s.fail_on is Severity.MEDIUM
    assert s.min_severity is Severity.LOW
    assert s.disabled == {"NWL014", "NWL020"}
    assert s.severity == {"NWL013": Severity.HIGH, "NWL022": Severity.MEDIUM}
    assert s.options["client_max_body_size_min"] == "128m"
    assert s.exclude == ["**/static-*.conf"]


def test_yaml_config():
    s = load_file(CONFIGS / "basic.yml")
    assert s.fail_on is Severity.HIGH
    assert s.disabled == {"NWL016"}
    assert s.options["extra_sensitive_paths"] == ["/private/export.csv"]


def test_pyproject_section(tmp_path):
    (tmp_path / "pyproject.toml").write_text((CONFIGS / "pyproject.toml").read_text())
    found = discover(tmp_path)
    assert found is not None and found.name == "pyproject.toml"
    assert load_file(found).disabled == {"NWL001"}


def test_discover_prefers_dedicated_file(tmp_path):
    (tmp_path / "pyproject.toml").write_text((CONFIGS / "pyproject.toml").read_text())
    (tmp_path / ".nginx-wp-lint.toml").write_text('fail_on = "high"\n')
    assert discover(tmp_path).name == ".nginx-wp-lint.toml"
    assert discover(tmp_path / "nowhere") is None


@pytest.mark.parametrize(
    ("data", "message"),
    [
        ({"fail_onn": "low"}, "unknown key"),
        ({"fail_on": "urgent"}, "unknown severity"),
        ({"disable": ["NWL999"]}, "unknown rule"),
        ({"disable": 5}, "list of rule ids"),
        ({"severity": {"NWL001": "loud"}}, "unknown severity"),
        ({"severity": ["x"]}, "table of rule"),
        ({"options": {"nope": 1}}, "unknown option"),
        ({"exclude": "x"}, "glob patterns"),
        ({"follow_includes": "yes"}, "true or false"),
        ({"prefix": 3}, "must be a string"),
    ],
)
def test_validation(data, message):
    with pytest.raises(ConfigError, match=message):
        apply_dict(Settings(), data)


def test_bad_files(tmp_path):
    with pytest.raises(ConfigError, match="unknown key"):
        load_file(CONFIGS / "bad-key.toml")
    with pytest.raises(ConfigError, match="not found"):
        load_file(tmp_path / "missing.toml")
    broken = tmp_path / "x.toml"
    broken.write_text("fail_on = \n")
    with pytest.raises(ConfigError, match="invalid TOML"):
        load_file(broken)
    broken_yaml = tmp_path / "x.yml"
    broken_yaml.write_text("- a\n- b\n")
    with pytest.raises(ConfigError, match="mapping"):
        load_file(broken_yaml)


def test_fail_on_never_and_disable_by_name():
    s = apply_dict(Settings(), {"fail_on": "never", "disable": "autoindex-on, NWL001"})
    assert s.fail_on is None
    assert s.disabled == {"NWL002", "NWL001"}


def test_settings_change_results():
    text = "server { listen 80; autoindex on; }"
    assert any(f.rule_id == "NWL002" for f in lint(text).findings)
    assert not any(f.rule_id == "NWL002" for f in lint(text, disabled={"NWL002"}).findings)
    raised = lint(text, severity={"NWL002": Severity.HIGH})
    assert next(f for f in raised.findings if f.rule_id == "NWL002").severity is Severity.HIGH
    assert all(f.severity.rank >= Severity.MEDIUM.rank
               for f in lint(text, min_severity=Severity.MEDIUM).findings)


def test_option_changes_threshold():
    text = "http { server { listen 80; index index.php; client_max_body_size 64m; } }"
    assert not lint(text, only=("NWL022",)).findings
    opts = dict(Settings().options, client_max_body_size_min="128m")
    assert lint(text, only=("NWL022",), options=opts).findings


def test_exclude():
    assert is_excluded("conf/static-only.conf", ["**/static-*.conf"])
    assert is_excluded("static-only.conf", ["static-*.conf"])
    assert not is_excluded("conf/site.conf", ["**/static-*.conf"])
    s = Settings(exclude=["*static-only.conf"])
    result = lint_paths([str(FIXTURES / "bad")], s)
    assert not any(r.endswith("static-only.conf") for r in result.roots)


def test_examples_load_and_hardened_example_is_clean():
    examples = FIXTURES.parent.parent / "examples"
    assert load_file(examples / ".nginx-wp-lint.toml").fail_on is Severity.MEDIUM
    assert load_file(examples / "nginx-wp-lint.yml").disabled == {"NWL014"}
    result = lint_paths([str(examples / "wordpress-hardened")], Settings())
    assert result.findings == []
