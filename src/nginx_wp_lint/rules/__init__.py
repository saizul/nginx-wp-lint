"""Rule registry."""

from __future__ import annotations

from . import correctness, headers, performance, security, tls, wordpress
from .base import DEFAULT_OPTIONS, Finding, LintContext, Rule, Severity

ALL_RULES: tuple[type[Rule], ...] = tuple(sorted(
    (*correctness.RULES, *security.RULES, *headers.RULES, *performance.RULES, *tls.RULES,
     *wordpress.RULES),
    key=lambda r: r.id,
))

RULES_BY_ID: dict[str, type[Rule]] = {r.id: r for r in ALL_RULES}
RULES_BY_NAME: dict[str, type[Rule]] = {r.name: r for r in ALL_RULES}


class UnknownRuleError(ValueError):
    pass


def lookup(ref: str) -> type[Rule]:
    """Find a rule by id (``NWL007``, case-insensitive) or name (``php-in-uploads``)."""
    key = ref.strip()
    rule = RULES_BY_ID.get(key.upper()) or RULES_BY_NAME.get(key.lower())
    if rule is None:
        raise UnknownRuleError(f"unknown rule {ref!r}; see `nginx-wp-lint --list-rules`")
    return rule


__all__ = [
    "ALL_RULES",
    "DEFAULT_OPTIONS",
    "RULES_BY_ID",
    "RULES_BY_NAME",
    "Finding",
    "LintContext",
    "Rule",
    "Severity",
    "UnknownRuleError",
    "lookup",
]
