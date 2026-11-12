"""GitHub Actions workflow commands (inline annotations in pull requests)."""

from __future__ import annotations

from ..linter import LintResult
from ..rules import Severity
from .paths import display_path

LEVEL = {Severity.HIGH: "error", Severity.MEDIUM: "warning", Severity.LOW: "warning",
         Severity.INFO: "notice"}


def _escape_data(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_prop(text: str) -> str:
    return _escape_data(text).replace(":", "%3A").replace(",", "%2C")


def render_github(result: LintResult, base: str = ".") -> str:
    lines = []
    for f in result.findings:
        props = (f"file={_escape_prop(display_path(f.file, base))},line={f.line},"
                 f"col={f.column},title={_escape_prop(f'{f.rule_id} {f.rule_name}')}")
        message = f.message + (f"\n{f.hint}" if f.hint else "")
        lines.append(f"::{LEVEL[f.severity]} {props}::{_escape_data(message)}")
    return "\n".join(lines) + ("\n" if lines else "")
