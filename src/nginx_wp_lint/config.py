"""Linter settings from TOML or YAML files and the command line."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .rules import ALL_RULES, DEFAULT_OPTIONS, Severity, UnknownRuleError, lookup

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised on 3.9/3.10 only
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None

CONFIG_NAMES = (".nginx-wp-lint.toml", "nginx-wp-lint.toml", ".nginx-wp-lint.yml",
                ".nginx-wp-lint.yaml")

KNOWN_KEYS = {"fail_on", "min_severity", "disable", "enable_only", "exclude", "severity",
              "options", "prefix", "follow_includes"}


class ConfigError(Exception):
    pass


@dataclass
class Settings:
    disabled: set[str] = field(default_factory=set)
    enable_only: set[str] = field(default_factory=set)
    severity: dict[str, Severity] = field(default_factory=dict)
    options: dict[str, Any] = field(default_factory=lambda: dict(DEFAULT_OPTIONS))
    exclude: list[str] = field(default_factory=list)
    fail_on: Severity | None = Severity.LOW  # None = never fail
    min_severity: Severity = Severity.INFO
    prefix: str | None = None
    follow_includes: bool = True
    source: str | None = None

    def rule_enabled(self, rule_id: str) -> bool:
        if self.enable_only and rule_id not in self.enable_only:
            return False
        return rule_id not in self.disabled

    def enabled_rules(self):
        return [r for r in ALL_RULES if self.rule_enabled(r.id)]


def _rule_ids(values: Any, key: str) -> set[str]:
    if isinstance(values, str):
        values = [v for v in values.replace(",", " ").split() if v]
    if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
        raise ConfigError(f"{key} must be a list of rule ids or names")
    out = set()
    for v in values:
        try:
            out.add(lookup(v).id)
        except UnknownRuleError as exc:
            raise ConfigError(f"{key}: {exc}") from exc
    return out


def _severity(value: Any, key: str, allow_never: bool = False) -> Severity | None:
    if allow_never and value in ("never", "none", None):
        return None
    if not isinstance(value, str):
        raise ConfigError(f"{key} must be a string")
    try:
        return Severity.parse(value)
    except ValueError as exc:
        raise ConfigError(f"{key}: {exc}") from exc


def apply_dict(settings: Settings, data: dict[str, Any], source: str = "config") -> Settings:
    unknown = set(data) - KNOWN_KEYS
    if unknown:
        raise ConfigError(f"{source}: unknown key(s): {', '.join(sorted(unknown))}")
    if "fail_on" in data:
        settings.fail_on = _severity(data["fail_on"], "fail_on", allow_never=True)
    if "min_severity" in data:
        sev = _severity(data["min_severity"], "min_severity")
        assert sev is not None
        settings.min_severity = sev
    if "disable" in data:
        settings.disabled |= _rule_ids(data["disable"], "disable")
    if "enable_only" in data:
        settings.enable_only = _rule_ids(data["enable_only"], "enable_only")
    if "exclude" in data:
        exclude = data["exclude"]
        if not isinstance(exclude, list) or not all(isinstance(e, str) for e in exclude):
            raise ConfigError("exclude must be a list of glob patterns")
        settings.exclude.extend(exclude)
    if "severity" in data:
        sev_map = data["severity"]
        if not isinstance(sev_map, dict):
            raise ConfigError("severity must be a table of rule = level")
        for ref, level in sev_map.items():
            try:
                rid = lookup(ref).id
            except UnknownRuleError as exc:
                raise ConfigError(f"severity: {exc}") from exc
            sev = _severity(level, f"severity.{ref}")
            assert sev is not None
            settings.severity[rid] = sev
    if "options" in data:
        opts = data["options"]
        if not isinstance(opts, dict):
            raise ConfigError("options must be a table")
        bad = set(opts) - set(DEFAULT_OPTIONS)
        if bad:
            raise ConfigError(f"unknown option(s): {', '.join(sorted(bad))}")
        settings.options.update(opts)
    if "prefix" in data:
        if not isinstance(data["prefix"], str):
            raise ConfigError("prefix must be a string")
        settings.prefix = data["prefix"]
    if "follow_includes" in data:
        if not isinstance(data["follow_includes"], bool):
            raise ConfigError("follow_includes must be true or false")
        settings.follow_includes = data["follow_includes"]
    return settings


def _load_toml(path: Path) -> dict[str, Any]:
    if tomllib is None:  # pragma: no cover
        raise ConfigError("TOML config on Python < 3.11 needs the 'tomli' package")
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: invalid TOML: {exc}") from exc
    if path.name == "pyproject.toml":
        return data.get("tool", {}).get("nginx-wp-lint", {})
    return data


def _load_yaml(path: Path) -> dict[str, Any]:
    try:
        import yaml
    except ImportError as exc:
        raise ConfigError(f"{path}: YAML config needs PyYAML "
                          "(pip install 'nginx-wp-lint[yaml]')") from exc
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path}: invalid YAML: {exc}") from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: the top level must be a mapping")
    return data


def load_file(path: str | Path, settings: Settings | None = None) -> Settings:
    p = Path(path)
    settings = settings or Settings()
    if not p.is_file():
        raise ConfigError(f"config file {p} not found")
    try:
        data = _load_yaml(p) if p.suffix in (".yml", ".yaml") else _load_toml(p)
    except OSError as exc:
        raise ConfigError(f"cannot read {p}: {exc.strerror or exc}") from exc
    settings.source = str(p)
    return apply_dict(settings, data, source=str(p))


def discover(start: str | Path = ".") -> Path | None:
    """Find a config file in ``start``: dedicated files first, then pyproject.toml."""
    base = Path(start)
    for name in CONFIG_NAMES:
        cand = base / name
        if cand.is_file():
            return cand
    pyproject = base / "pyproject.toml"
    if pyproject.is_file() and tomllib is not None:
        try:
            data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError):
            return None
        if "nginx-wp-lint" in data.get("tool", {}):
            return pyproject
    return None


def is_excluded(path: str, patterns: list[str]) -> bool:
    from fnmatch import fnmatch

    norm = path.replace(os.sep, "/")
    return any(fnmatch(norm, pat) or fnmatch(os.path.basename(norm), pat) for pat in patterns)
