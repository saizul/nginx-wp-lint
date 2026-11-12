"""Response headers in effect for a server or location.

``add_header`` is inherited from the previous level only if the current level
has no ``add_header`` of its own. That is the classic way security headers
disappear: one ``add_header Cache-Control ...`` in a location drops every
header set in the server block. ``add_header_inherit merge;`` (nginx 1.29.3+)
changes that, and ``more_set_headers`` (headers-more module) is applied at
every level, so both are taken into account.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .model import has_unresolved_include, levels_up
from .parser import Directive


@dataclass
class HeaderSet:
    headers: dict[str, Directive] = field(default_factory=dict)  # lower-case name -> directive
    level: Directive | None = None  # level whose add_header directives apply
    uncertain: bool = False  # an unresolved include may add headers

    def get(self, name: str) -> Directive | None:
        return self.headers.get(name.lower())

    def has(self, name: str) -> bool:
        return name.lower() in self.headers

    def value(self, name: str) -> str | None:
        d = self.get(name)
        if d is None:
            return None
        return header_value(d, name)


def header_value(d: Directive, name: str) -> str:
    if d.name == "add_header":
        return d.arg(1)
    for arg in d.args:
        if ":" in arg and arg.split(":", 1)[0].strip().lower() == name.lower():
            return arg.split(":", 1)[1].strip()
    return ""


def more_set_header_names(d: Directive) -> list[str]:
    names = []
    skip_next = False
    for arg in d.args:
        if skip_next:
            skip_next = False
            continue
        if arg in ("-s", "-t"):
            skip_next = True
            continue
        if ":" in arg:
            names.append(arg.split(":", 1)[0].strip().lower())
    return names


def effective_headers(node: Directive) -> HeaderSet:
    result = HeaderSet()
    merging = True
    defined = False
    for level in levels_up(node):
        for d in level.children:
            if d.name == "more_set_headers":
                for name in more_set_header_names(d):
                    result.headers.setdefault(name, d)
        if not merging:
            continue
        adds = [d for d in level.children if d.name == "add_header" and d.args]
        if has_unresolved_include(level, ("add_header",)):
            result.uncertain = True
        if adds:
            for d in adds:
                result.headers.setdefault(d.arg(0).lower(), d)
            if not defined:
                result.level = level
                defined = True
            inherit = [d for d in level.children if d.name == "add_header_inherit"]
            if not (inherit and inherit[-1].arg(0) == "merge"):
                merging = False
    return result


def own_add_headers(level: Directive) -> list[Directive]:
    return [d for d in level.children if d.name == "add_header" and d.args]
