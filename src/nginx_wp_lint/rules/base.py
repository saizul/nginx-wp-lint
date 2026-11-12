"""Rule base class, findings and the context rules run in."""

from __future__ import annotations

import enum
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any, ClassVar

from ..loader import LoadedConfig
from ..model import ServerInfo, collect_servers
from ..parser import Directive


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return _RANK[self]

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls(value.lower())
        except ValueError:
            names = ", ".join(s.value for s in cls)
            raise ValueError(f"unknown severity {value!r} (expected {names})") from None


_RANK = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3}


@dataclass
class Finding:
    rule_id: str
    rule_name: str
    severity: Severity
    message: str
    file: str
    line: int
    column: int = 1
    hint: str = ""
    context: str = ""  # e.g. the server name

    def sort_key(self) -> tuple[str, int, int, str]:
        return (self.file, self.line, self.column, self.rule_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule_id,
            "name": self.rule_name,
            "severity": self.severity.value,
            "message": self.message,
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "hint": self.hint,
            "context": self.context,
        }


DEFAULT_OPTIONS: dict[str, Any] = {
    "client_max_body_size_min": "8m",
    "hsts_min_max_age": 15552000,  # 180 days
    "logged_in_cookie": "wordpress_logged_in",
    "extra_sensitive_paths": [],
}


@dataclass
class LintContext:
    config: LoadedConfig
    options: dict[str, Any] = field(default_factory=lambda: dict(DEFAULT_OPTIONS))
    _servers: list[ServerInfo] | None = None

    @property
    def root(self) -> Directive:
        return self.config.root

    @property
    def servers(self) -> list[ServerInfo]:
        if self._servers is None:
            self._servers = collect_servers(self.root)
        return self._servers

    @property
    def http_blocks(self) -> list[Directive]:
        return [d for d in self.root.walk() if d.name == "http" and d.is_block]

    @property
    def fragment(self) -> bool:
        """True when the input has no ``http`` block (a site file on its own),
        so http-level settings from ``nginx.conf`` are unknown."""
        return not self.http_blocks

    def content_servers(self, php_only: bool = False) -> list[ServerInfo]:
        out = []
        for s in self.servers:
            if s.is_redirect_only:
                continue
            if php_only and not s.is_php:
                continue
            out.append(s)
        return out

    def walk(self) -> Iterator[Directive]:
        return self.root.walk()

    def named(self, *names: str) -> Iterator[Directive]:
        wanted = set(names)
        for d in self.root.walk():
            if d.name in wanted:
                yield d


class Rule:
    """Subclasses set the class attributes and implement :meth:`check`."""

    id: ClassVar[str] = ""
    name: ClassVar[str] = ""
    severity: ClassVar[Severity] = Severity.LOW
    category: ClassVar[str] = ""
    summary: ClassVar[str] = ""
    hint: ClassVar[str] = ""
    # Settings that normally live in the http block of nginx.conf. When the
    # input has no http block and the setting is simply absent, the finding is
    # downgraded to info (nginx.conf may well set it).
    http_level: ClassVar[bool] = False

    def check(self, ctx: LintContext) -> Iterator[Finding]:  # pragma: no cover - abstract
        raise NotImplementedError

    def finding(self, node: Directive, message: str, *, severity: Severity | None = None,
                hint: str | None = None, server: ServerInfo | None = None,
                ctx: LintContext | None = None, unset: bool = False) -> Finding:
        sev = severity or self.severity
        if unset and self.http_level and ctx is not None and ctx.fragment:
            sev = Severity.INFO
            message += " (not set in this file; ignore if nginx.conf sets it in the http block)"
        return Finding(
            rule_id=self.id,
            rule_name=self.name,
            severity=sev,
            message=message,
            file=node.file,
            line=node.line,
            column=node.column,
            hint=self.hint if hint is None else hint,
            context=server.label if server else "",
        )
