"""Run the rules over files and apply configuration and suppressions."""

from __future__ import annotations

import os
from collections.abc import Iterable
from dataclasses import dataclass, field

from . import suppress
from .config import Settings, is_excluded
from .loader import LoadedConfig, load
from .parser import ROOT, Directive, ParsedFile, parse_string
from .rules import RULES_BY_ID, Finding, LintContext, Severity
from .rules.correctness import ParseErrorRule


@dataclass
class LintResult:
    findings: list[Finding] = field(default_factory=list)
    files: list[str] = field(default_factory=list)  # every file read, includes too
    roots: list[str] = field(default_factory=list)
    parse_errors: int = 0
    suppressed: int = 0
    baselined: int = 0  # findings accepted by --baseline
    baseline_stale: int = 0  # baseline entries that no longer match anything
    warnings: list[str] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.value] += 1
        return out

    def worst(self) -> Severity | None:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: s.rank)


def expand_paths(paths: Iterable[str], exclude: list[str]) -> list[str]:
    """Files to lint as roots. A directory with nginx.conf means that file;
    otherwise every ``*.conf`` below it."""
    out: list[str] = []
    for p in paths:
        if os.path.isdir(p):
            main = os.path.join(p, "nginx.conf")
            if os.path.isfile(main):
                candidates = [main]
            else:
                candidates = []
                for dirpath, dirnames, filenames in os.walk(p):
                    dirnames.sort()
                    for name in sorted(filenames):
                        if _looks_like_config(dirpath, name):
                            candidates.append(os.path.join(dirpath, name))
        else:
            candidates = [p]
        for c in candidates:
            norm = os.path.normpath(c)
            if not is_excluded(norm, exclude) and norm not in out:
                out.append(norm)
    # nginx.conf first, so that files it includes are not linted twice.
    out.sort(key=lambda f: 0 if os.path.basename(f) == "nginx.conf" else 1)
    return out


SITE_DIRS = ("sites-enabled", "sites-available")


def _looks_like_config(dirpath: str, name: str) -> bool:
    """``*.conf`` files, plus extension-less files in sites-enabled/available
    (Debian and Ubuntu name site files ``default`` or ``example.com``)."""
    if name.startswith(".") or name.endswith(("~", ".bak", ".swp", ".orig", ".dpkg-dist")):
        return False
    if name.endswith(".conf"):
        return True
    return os.path.basename(dirpath) in SITE_DIRS


def _parse_error_finding(err) -> Finding:
    rule = ParseErrorRule
    return Finding(rule_id=rule.id, rule_name=rule.name, severity=Severity.HIGH,
                   message=err.message, file=err.file, line=max(err.line, 1),
                   column=max(err.column, 1), hint=rule.hint)


def lint_loaded(config: LoadedConfig, settings: Settings,
                result: LintResult | None = None) -> LintResult:
    result = result or LintResult()
    raw: list[Finding] = [_parse_error_finding(e) for e in config.errors]
    result.parse_errors += len(config.errors)
    if config.root.block or not config.errors:
        ctx = LintContext(config=config, options=dict(settings.options))
        for rule_cls in settings.enabled_rules():
            raw.extend(rule_cls().check(ctx))

    sups: dict[str, suppress.FileSuppressions] = {}
    for path, parsed in config.files.items():
        sups[path] = suppress.build(parsed, result.warnings)

    seen = {(f.rule_id, f.file, f.line, f.column, f.message) for f in result.findings}
    for f in raw:
        if f.rule_id != ParseErrorRule.id and not settings.rule_enabled(f.rule_id):
            continue
        if f.rule_id in settings.severity:
            f.severity = settings.severity[f.rule_id]
        if f.severity.rank < settings.min_severity.rank:
            continue
        sup = sups.get(f.file)
        if sup is not None and sup.suppresses(f):
            result.suppressed += 1
            continue
        key = (f.rule_id, f.file, f.line, f.column, f.message)
        if key in seen:
            continue
        seen.add(key)
        result.findings.append(f)
    for path in config.files:
        if path not in result.files:
            result.files.append(path)
    if config.path not in result.files:
        result.files.append(config.path)
    result.findings.sort(key=Finding.sort_key)
    return result


def lint_paths(paths: Iterable[str], settings: Settings | None = None) -> LintResult:
    settings = settings or Settings()
    result = LintResult()
    roots = expand_paths(paths, settings.exclude)
    seen_files: set[str] = set()
    for root in roots:
        if os.path.abspath(root) in seen_files:
            continue
        config = load(root, prefix=settings.prefix, follow_includes=settings.follow_includes)
        result.roots.append(config.path)
        seen_files.update(os.path.abspath(p) for p in config.files)
        lint_loaded(config, settings, result)
    return result


def lint_string(text: str, path: str = "nginx.conf",
                settings: Settings | None = None) -> LintResult:
    """Lint configuration text without touching the file system (no includes)."""
    settings = settings or Settings()
    root = Directive(name=ROOT, args=[], file=path, line=0, block=[])
    config = LoadedConfig(path=path, root=root)
    from .parser import ParseError

    try:
        parsed: ParsedFile = parse_string(text, path)
    except ParseError as exc:
        config.errors.append(exc)
    else:
        config.files[path] = parsed
        root.block = parsed.directives
        for d in root.block:
            d.parent = root
        for d in root.walk():
            if d.name == "include":
                d.include_resolved = False
                config.missing_includes.append(d)
    return lint_loaded(config, settings)


def rule_for(finding: Finding):
    return RULES_BY_ID.get(finding.rule_id)
