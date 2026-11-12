from __future__ import annotations

import json

from .._version import __version__
from ..linter import LintResult
from .paths import display_path


def render_json(result: LintResult, base: str = ".") -> str:
    findings = []
    for f in result.findings:
        item = f.to_dict()
        item["file"] = display_path(f.file, base)
        findings.append(item)
    data = {
        "tool": {"name": "nginx-wp-lint", "version": __version__},
        "summary": {
            "files": len(result.files),
            "problems": len(result.findings),
            "suppressed": result.suppressed,
            "parse_errors": result.parse_errors,
            "by_severity": result.counts(),
        },
        "files": [display_path(p, base) for p in result.files],
        "findings": findings,
    }
    return json.dumps(data, indent=2) + "\n"
