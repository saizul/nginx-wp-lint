"""Baseline files: accept the problems that exist today, fail only on new ones.

A baseline is a JSON file listing a fingerprint for every finding of a run.
Later runs drop findings whose fingerprint is in the baseline, so a large
existing configuration can adopt the linter in CI without fixing everything
first.

Fingerprints do not contain line or column numbers. They are built from the
rule id, the file path (relative to ``--base``), the server context, the
message and the whitespace-normalised text of the source line, so adding or
removing lines elsewhere in a file does not invalidate the baseline, while
editing the offending directive does. Identical fingerprints are counted: a
baseline with two entries for the same problem accepts at most two copies.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from ._version import __version__
from .output.paths import display_path
from .rules import Finding

FORMAT_VERSION = 1


class BaselineError(Exception):
    pass


class _SourceCache:
    """Read each source file once; missing or unreadable files give ''."""

    def __init__(self) -> None:
        self._lines: dict[str, list[str]] = {}

    def line(self, path: str, number: int) -> str:
        if path not in self._lines:
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    self._lines[path] = fh.read().splitlines()
            except OSError:
                self._lines[path] = []
        lines = self._lines[path]
        if 1 <= number <= len(lines):
            return " ".join(lines[number - 1].split())
        return ""


def fingerprint(finding: Finding, base: str = ".", source: _SourceCache | None = None) -> str:
    """Stable, line-number independent identifier for a finding."""
    source = source or _SourceCache()
    uri = display_path(finding.file, base)
    text = source.line(finding.file, finding.line)
    raw = "|".join((finding.rule_id, uri, finding.context, finding.message, text))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@dataclass
class BaselineEntry:
    fingerprint: str
    rule: str
    file: str
    line: int
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {"fingerprint": self.fingerprint, "rule": self.rule, "file": self.file,
                "line": self.line, "message": self.message}


@dataclass
class Baseline:
    entries: list[BaselineEntry] = field(default_factory=list)

    @classmethod
    def from_findings(cls, findings: Iterable[Finding], base: str = ".") -> Baseline:
        source = _SourceCache()
        entries = [
            BaselineEntry(fingerprint=fingerprint(f, base, source), rule=f.rule_id,
                          file=display_path(f.file, base), line=f.line, message=f.message)
            for f in findings
        ]
        entries.sort(key=lambda e: (e.file, e.line, e.rule, e.fingerprint))
        return cls(entries)

    def counts(self) -> Counter[str]:
        return Counter(e.fingerprint for e in self.entries)

    def to_json(self) -> str:
        data = {
            "tool": "nginx-wp-lint",
            "tool_version": __version__,
            "format": FORMAT_VERSION,
            "entries": [e.to_dict() for e in self.entries],
        }
        return json.dumps(data, indent=2) + "\n"

    def write(self, path: str) -> None:
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(self.to_json())
        except OSError as exc:
            raise BaselineError(f"cannot write baseline {path}: {exc.strerror or exc}") from exc


def parse(text: str, source: str = "baseline") -> Baseline:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise BaselineError(f"{source}: invalid JSON: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("entries"), list):
        raise BaselineError(f"{source}: not an nginx-wp-lint baseline (no 'entries' list)")
    fmt = data.get("format", FORMAT_VERSION)
    if fmt != FORMAT_VERSION:
        raise BaselineError(f"{source}: unsupported baseline format {fmt!r} "
                            f"(this version reads format {FORMAT_VERSION})")
    entries = []
    for i, item in enumerate(data["entries"]):
        if not isinstance(item, dict) or not isinstance(item.get("fingerprint"), str):
            raise BaselineError(f"{source}: entry {i} has no fingerprint")
        line = item.get("line", 0)
        entries.append(BaselineEntry(
            fingerprint=item["fingerprint"],
            rule=str(item.get("rule", "")),
            file=str(item.get("file", "")),
            line=line if isinstance(line, int) else 0,
            message=str(item.get("message", "")),
        ))
    return Baseline(entries)


def load(path: str) -> Baseline:
    if not os.path.isfile(path):
        raise BaselineError(f"baseline file {path} not found")
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        raise BaselineError(f"cannot read baseline {path}: {exc.strerror or exc}") from exc
    return parse(text, source=path)


@dataclass
class BaselineMatch:
    new: list[Finding]
    matched: int
    stale: list[BaselineEntry]


def apply(findings: Iterable[Finding], baseline: Baseline, base: str = ".") -> BaselineMatch:
    """Split findings into new ones and those accepted by the baseline.

    ``stale`` lists baseline entries that matched nothing: problems that were
    fixed (or changed) since the baseline was written.
    """
    remaining = baseline.counts()
    source = _SourceCache()
    new: list[Finding] = []
    matched = 0
    for f in findings:
        fp = fingerprint(f, base, source)
        if remaining[fp] > 0:
            remaining[fp] -= 1
            matched += 1
        else:
            new.append(f)
    stale: list[BaselineEntry] = []
    for entry in baseline.entries:
        if remaining[entry.fingerprint] > 0:
            remaining[entry.fingerprint] -= 1
            stale.append(entry)
    return BaselineMatch(new=new, matched=matched, stale=stale)
