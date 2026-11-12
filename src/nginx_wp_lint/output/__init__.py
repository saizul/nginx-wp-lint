"""Output formats: text, JSON, SARIF 2.1.0 and GitHub workflow annotations."""

from __future__ import annotations

from ..linter import LintResult
from .github import render_github
from .json_out import render_json
from .sarif import render_sarif
from .text import render_text

FORMATS = ("text", "json", "sarif", "github")


def render(result: LintResult, fmt: str, *, base: str = ".", quiet: bool = False) -> str:
    if fmt == "text":
        return render_text(result, base=base, quiet=quiet)
    if fmt == "json":
        return render_json(result, base=base)
    if fmt == "sarif":
        return render_sarif(result, base=base)
    if fmt == "github":
        return render_github(result, base=base)
    raise ValueError(f"unknown format {fmt!r}; choose from {', '.join(FORMATS)}")


__all__ = ["FORMATS", "render"]
