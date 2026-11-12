"""SARIF 2.1.0 output for GitHub code scanning and other SARIF viewers."""

from __future__ import annotations

import hashlib
import json

from .._version import __version__
from ..linter import LintResult
from ..rules import ALL_RULES, Severity
from .paths import display_path

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFO_URI = "https://github.com/saizul/nginx-wp-lint"

LEVEL = {Severity.HIGH: "error", Severity.MEDIUM: "warning", Severity.LOW: "note",
         Severity.INFO: "note"}
# GitHub code scanning reads properties["security-severity"] (0.0-10.0).
SECURITY_SEVERITY = {Severity.HIGH: "8.0", Severity.MEDIUM: "5.5", Severity.LOW: "3.0",
                     Severity.INFO: "1.0"}


def _rule_descriptor(rule) -> dict:
    return {
        "id": rule.id,
        "name": rule.name,
        "shortDescription": {"text": rule.summary},
        "fullDescription": {"text": rule.summary},
        "help": {"text": rule.hint, "markdown": rule.hint},
        "helpUri": f"{INFO_URI}#rule-reference",
        "defaultConfiguration": {"level": LEVEL[rule.severity]},
        "properties": {
            "tags": ["nginx", rule.category] + (["security"] if rule.category in (
                "security", "headers", "tls", "wordpress") else []),
            "precision": "high",
            "problem.severity": LEVEL[rule.severity].replace("note", "recommendation"),
            "security-severity": SECURITY_SEVERITY[rule.severity],
        },
    }


def render_sarif(result: LintResult, base: str = ".") -> str:
    rules = list(ALL_RULES)
    index = {r.id: i for i, r in enumerate(rules)}
    results = []
    for f in result.findings:
        uri = display_path(f.file, base)
        fingerprint = hashlib.sha256(
            f"{f.rule_id}|{uri}|{f.context}|{f.message}".encode()).hexdigest()
        results.append({
            "ruleId": f.rule_id,
            "ruleIndex": index.get(f.rule_id, 0),
            "level": LEVEL[f.severity],
            "message": {"text": f.message + (f" Fix: {f.hint}" if f.hint else "")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": f.line, "startColumn": f.column},
                },
            }],
            "partialFingerprints": {"nginxWpLint/v1": fingerprint},
            "properties": {"severity": f.severity.value,
                           "security-severity": SECURITY_SEVERITY[f.severity]},
        })
    doc = {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "nginx-wp-lint",
                "version": __version__,
                "semanticVersion": __version__,
                "informationUri": INFO_URI,
                "rules": [_rule_descriptor(r) for r in rules],
            }},
            "invocations": [{"executionSuccessful": result.parse_errors == 0}],
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2) + "\n"
