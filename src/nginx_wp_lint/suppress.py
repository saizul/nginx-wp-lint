"""Inline suppression comments.

Supported forms (rule ids or names, comma separated, or ``all``)::

    server_tokens on;  # nginx-wp-lint: disable=NWL001     (this line only)
    # nginx-wp-lint: disable-next-line=xmlrpc-not-blocked  (the next directive)
    # nginx-wp-lint: disable=NWL060                        (until enable or end of block)
    # nginx-wp-lint: enable=NWL060
    # nginx-wp-lint: disable-file=NWL014                   (the whole file)

A ``disable`` comment that is the first thing inside a block also covers the
block's opening line, so findings reported on ``server {`` are suppressed by a
comment placed just inside it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .parser import Directive, ParsedFile
from .rules import UnknownRuleError, lookup
from .rules.base import Finding

COMMENT_RE = re.compile(
    r"^\s*nginx-wp-lint\s*:\s*(disable-next-line|disable-line|disable-file|disable|enable)"
    r"(?:\s*[=\s]\s*(?P<ids>.+?))?\s*$",
    re.IGNORECASE,
)

ALL = "*"


def parse_ids(text: str | None, warnings: list[str], where: str) -> set[str]:
    if not text or text.strip().lower() == "all":
        return {ALL}
    out = set()
    for part in re.split(r"[,\s]+", text.strip()):
        if not part:
            continue
        if part.lower() == "all":
            out.add(ALL)
            continue
        try:
            out.add(lookup(part).id)
        except UnknownRuleError:
            warnings.append(f"{where}: unknown rule {part!r} in suppression comment")
    return out


@dataclass
class _Range:
    start: int
    end: int
    ids: set[str]


@dataclass
class FileSuppressions:
    file_wide: set[str] = field(default_factory=set)
    lines: dict[int, set[str]] = field(default_factory=dict)
    ranges: list[_Range] = field(default_factory=list)

    def suppresses(self, finding: Finding) -> bool:
        def hit(ids: set[str]) -> bool:
            return ALL in ids or finding.rule_id in ids

        if hit(self.file_wide):
            return True
        if hit(self.lines.get(finding.line, set())):
            return True
        return any(r.start <= finding.line <= r.end and hit(r.ids) for r in self.ranges)


def _directive_lines(directives: list[Directive], path: str) -> list[int]:
    lines = set()
    stack = list(directives)
    while stack:
        d = stack.pop()
        if d.file == path:
            lines.add(d.line)
        stack.extend(d.children)
    return sorted(lines)


def build(parsed: ParsedFile, warnings: list[str]) -> FileSuppressions:
    sup = FileSuppressions()
    directive_lines = _directive_lines(parsed.directives, parsed.path)
    open_ranges: list[_Range] = []
    for c in sorted(parsed.comments, key=lambda c: c.line):
        m = COMMENT_RE.match(c.text)
        if not m:
            continue
        kind = m.group(1).lower()
        where = f"{parsed.path}:{c.line}"
        ids = parse_ids(m.group("ids"), warnings, where)
        if not ids:
            continue
        if kind == "disable-file":
            sup.file_wide |= ids
        elif kind == "disable-line" or (kind == "disable" and not c.standalone):
            sup.lines.setdefault(c.line, set()).update(ids)
        elif kind == "disable-next-line":
            nxt = next((ln for ln in directive_lines if ln > c.line), None)
            if nxt is not None:
                sup.lines.setdefault(nxt, set()).update(ids)
        elif kind == "disable":
            start = c.line
            if c.first_in_block and c.block_start is not None:
                start = c.block_start
            end = c.block_end if c.block_end is not None else parsed.line_count
            rng = _Range(start, end, set(ids))
            sup.ranges.append(rng)
            open_ranges.append(rng)
        elif kind == "enable":
            for rng in open_ranges:
                if rng.start <= c.line <= rng.end and (ALL in ids or rng.ids & ids
                                                       or ALL in rng.ids):
                    rng.end = c.line
    return sup

