from __future__ import annotations

from ..linter import LintResult
from .paths import display_path


def render_text(result: LintResult, base: str = ".", quiet: bool = False) -> str:
    lines = []
    for f in result.findings:
        where = f"{display_path(f.file, base)}:{f.line}:{f.column}"
        ctx = f" [{f.context}]" if f.context else ""
        lines.append(f"{where}: {f.severity.value} {f.rule_id} {f.rule_name}: {f.message}{ctx}")
        if f.hint and not quiet:
            lines.append(f"    hint: {f.hint}")
    if not quiet:
        counts = result.counts()
        total = len(result.findings)
        files = len(result.files)
        if total:
            parts = ", ".join(f"{counts[k]} {k}" for k in ("high", "medium", "low", "info")
                              if counts[k])
            summary = f"{total} problem{'s' if total != 1 else ''} ({parts}) in {files} " \
                      f"file{'s' if files != 1 else ''}"
        else:
            summary = f"no problems in {files} file{'s' if files != 1 else ''}"
        if result.suppressed:
            summary += f", {result.suppressed} suppressed"
        if result.baselined:
            summary += f", {result.baselined} baselined"
        if lines:
            lines.append("")
        lines.append(summary)
    return "\n".join(lines) + ("\n" if lines else "")
