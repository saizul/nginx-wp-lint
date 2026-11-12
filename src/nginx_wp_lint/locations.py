"""Which ``location`` handles a URI, and what happens to the request there.

The matching follows ``ngx_http_core_find_location``:

1. An exact (``=``) match wins immediately.
2. Otherwise the longest prefix match is remembered and its nested
   locations are searched the same way; a final match inside wins.
3. Unless that prefix used ``^~``, regex locations of the current level are
   tried in order and the first match wins (then its nested locations).
4. Otherwise the remembered prefix match is used.

Rules use this to ask concrete questions such as "is ``/.git/config``
denied?" instead of pattern matching the configuration text.
"""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass, field

from .model import ServerInfo, has_unresolved_include, is_redirect_return, levels_up
from .parser import Directive


@dataclass(eq=False)
class Location:
    directive: Directive
    modifier: str  # "", "=", "^~", "~", "~*", "@"
    pattern: str
    regex: re.Pattern[str] | None = None
    regex_error: str | None = None

    @property
    def is_regex(self) -> bool:
        return self.modifier in ("~", "~*")

    @property
    def is_named(self) -> bool:
        return self.modifier == "@"

    def nested(self) -> list[Location]:
        return parse_locations(self.directive)

    def __str__(self) -> str:
        return f"location {self.modifier + ' ' if self.modifier else ''}{self.pattern}"


def pcre_to_python(pattern: str) -> str:
    """Translate the PCRE features commonly used in nginx to Python ``re``."""
    out = re.sub(r"\(\?<([A-Za-z_][A-Za-z0-9_]*)>", r"(?P<\1>", pattern)
    out = re.sub(r"\(\?'([A-Za-z_][A-Za-z0-9_]*)'", r"(?P<\1>", out)
    return out


def compile_pcre(pattern: str, case_insensitive: bool) -> tuple[re.Pattern[str] | None,
                                                                str | None]:
    try:
        flags = re.IGNORECASE if case_insensitive else 0
        return re.compile(pcre_to_python(pattern), flags), None
    except re.error as exc:
        return None, str(exc)


def parse_location(d: Directive) -> Location:
    args = list(d.args)
    modifier = ""
    pattern = ""
    if len(args) >= 2 and args[0] in ("=", "^~", "~", "~*"):
        modifier, pattern = args[0], args[1]
    elif args:
        first = args[0]
        if first.startswith("@"):
            modifier, pattern = "@", first[1:]
        elif first.startswith("^~") and len(first) > 2:
            modifier, pattern = "^~", first[2:]
        elif first.startswith("~*") and len(first) > 2:
            modifier, pattern = "~*", first[2:]
        elif first.startswith("~") and len(first) > 1:
            modifier, pattern = "~", first[1:]
        elif first.startswith("=") and len(first) > 1:
            modifier, pattern = "=", first[1:]
        else:
            pattern = first
    loc = Location(directive=d, modifier=modifier, pattern=pattern)
    if loc.is_regex:
        loc.regex, loc.regex_error = compile_pcre(pattern, modifier == "~*")
    return loc


def parse_locations(parent: Directive) -> list[Location]:
    return [parse_location(d) for d in parent.children if d.name == "location"]


@dataclass
class Match:
    chain: list[Location]
    final: bool


def _find(locations: list[Location], uri: str) -> Match:
    exact = next((loc for loc in locations if loc.modifier == "=" and loc.pattern == uri), None)
    if exact is not None:
        return Match([exact, *_find(exact.nested(), uri).chain], True)
    prefixes = [loc for loc in locations if loc.modifier in ("", "^~")
                and uri.startswith(loc.pattern)]
    chain: list[Location] = []
    noregex = False
    if prefixes:
        best = max(prefixes, key=lambda loc: len(loc.pattern))
        noregex = best.modifier == "^~"
        chain = [best]
        inner = _find(best.nested(), uri)
        if inner.final:
            return Match(chain + inner.chain, True)
        chain += inner.chain
    if not noregex:
        for loc in locations:
            if loc.is_regex and loc.regex is not None and loc.regex.search(uri):
                inner = _find(loc.nested(), uri)
                return Match([loc, *inner.chain], True)
    return Match(chain, False)


def find_location(server: Directive, uri: str) -> list[Location]:
    """The chain of locations (outermost first) that handles ``uri``."""
    return _find(parse_locations(server), uri).chain


class Outcome(enum.Enum):
    DENIED = "denied"  # 403/404/444, deny all, internal: the file is not served
    REDIRECT = "redirect"
    PHP = "php"  # handed to PHP-FPM (or another FastCGI server)
    STATIC = "static"  # served from disk if the file exists
    PROXY = "proxy"  # passed to an upstream: unknown
    UNKNOWN = "unknown"  # depends on something we cannot see

    @property
    def serves_file(self) -> bool:
        return self is Outcome.STATIC


@dataclass
class Resolution:
    uri: str
    outcome: Outcome
    chain: list[Location] = field(default_factory=list)
    decided_by: Directive | None = None
    reason: str = ""

    @property
    def leaf(self) -> Location | None:
        return self.chain[-1] if self.chain else None

    def describe(self) -> str:
        if self.leaf is not None:
            return f"{self.leaf} (line {self.leaf.directive.line})"
        if self.decided_by is not None:
            return f"`{self.decided_by}` at line {self.decided_by.line}"
        return "the server block (no location matches)"


URI_VARIABLES = ("$uri", "$request_uri", "$document_uri", "$fastcgi_script_name")


def evaluate_if(d: Directive, uri: str) -> bool | None:
    """Evaluate an ``if`` condition about the request URI.

    Returns True/False when the condition only tests a URI variable with a
    regex or string comparison, otherwise None (unknown).
    """
    args = list(d.args)
    if not args:
        return None
    text = " ".join(args)
    text = text.strip()
    if text.startswith("(") and text.endswith(")"):
        text = text[1:-1].strip()
    parts = text.split(None, 2)
    if len(parts) == 3 and parts[0] in URI_VARIABLES:
        _var, op, value = parts
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        subject = uri
        if op in ("=", "!="):
            result = subject == value
            return result if op == "=" else not result
        if op in ("~", "~*", "!~", "!~*"):
            regex, _err = compile_pcre(value, op.endswith("*"))
            if regex is None:
                return None
            result = bool(regex.search(subject))
            return not result if op.startswith("!") else result
    return None


def _decisive(level: Directive, uri: str, allow_conditions: bool = True
              ) -> tuple[Outcome, Directive, str] | None:
    """Outcome decided by rewrite-phase directives directly in ``level``."""
    for d in level.children:
        if d.name == "return":
            if is_redirect_return(d):
                return Outcome.REDIRECT, d, "return redirects"
            return Outcome.DENIED, d, f"return {d.arg(0)}"
        if d.name == "rewrite" and len(d.args) >= 2:
            regex, _ = compile_pcre(d.args[0], False)
            if regex is not None and regex.search(uri):
                flag = d.args[2] if len(d.args) > 2 else ""
                if flag in ("redirect", "permanent") or d.args[1].startswith(
                        ("http://", "https://", "$scheme")):
                    return Outcome.REDIRECT, d, "rewrite redirects"
                return Outcome.UNKNOWN, d, "rewritten internally"
        if d.name == "if" and allow_conditions:
            verdict = evaluate_if(d, uri)
            if verdict:
                inner = _decisive(d, uri, allow_conditions=False)
                if inner is not None:
                    return inner
                if any(c.name == "deny" and c.arg(0) == "all" for c in d.children):
                    return Outcome.DENIED, d, "if ... deny all"
    return None


def _access_denied(levels: list[Directive]) -> Directive | None:
    """``deny all`` in effect after allow/deny inheritance, if any."""
    for level in levels:
        rules = [d for d in level.children if d.name in ("allow", "deny")]
        if rules:
            for d in rules:
                if d.name == "deny" and d.arg(0) == "all":
                    return d
                if d.name == "allow" and d.arg(0) == "all":
                    return None
            return None
    return None


def resolve(server: ServerInfo | Directive, uri: str) -> Resolution:
    """What the server does with a request for ``uri``."""
    sdir = server.directive if isinstance(server, ServerInfo) else server
    decided = _decisive(sdir, uri)
    if decided is not None:
        return Resolution(uri, decided[0], [], decided[1], decided[2])
    chain = find_location(sdir, uri)
    if not chain:
        if has_unresolved_include(sdir):
            return Resolution(uri, Outcome.UNKNOWN, [], None, "unresolved include in server")
        denied = _access_denied(list(levels_up(sdir)))
        if denied is not None:
            return Resolution(uri, Outcome.DENIED, [], denied, "deny all")
        return Resolution(uri, Outcome.STATIC, [], None, "no location matches")
    leaf = chain[-1].directive
    if chain[-1].modifier != "=" and (
            has_unresolved_include(sdir)
            or any(has_unresolved_include(loc.directive) for loc in chain[:-1])):
        # A location defined in a file we could not read might match first.
        return Resolution(uri, Outcome.UNKNOWN, chain, None,
                          "unresolved include may define other locations")
    decided = _decisive(leaf, uri)
    if decided is not None:
        return Resolution(uri, decided[0], chain, decided[1], decided[2])
    internal = leaf.first("internal")
    if internal is not None:
        return Resolution(uri, Outcome.DENIED, chain, internal, "internal location")
    denied = _access_denied(list(levels_up(leaf)))
    if denied is not None:
        return Resolution(uri, Outcome.DENIED, chain, denied, "deny all")
    for name in ("fastcgi_pass",):
        d = leaf.first(name)
        if d is not None:
            return Resolution(uri, Outcome.PHP, chain, d, name)
    for name in ("proxy_pass", "uwsgi_pass", "scgi_pass", "grpc_pass", "memcached_pass"):
        d = leaf.first(name)
        if d is not None:
            return Resolution(uri, Outcome.PROXY, chain, d, name)
    if has_unresolved_include(leaf):
        return Resolution(uri, Outcome.UNKNOWN, chain, None, "unresolved include in location")
    if any(c.name == "if" for c in leaf.children):
        return Resolution(uri, Outcome.UNKNOWN, chain, None, "conditional configuration")
    if leaf.first("try_files") is not None:
        tf = leaf.first("try_files")
        assert tf is not None
        if not any(a.startswith("$uri") or a.startswith("$request_filename")
                   for a in tf.args[:-1]):
            return Resolution(uri, Outcome.UNKNOWN, chain, tf, "try_files without $uri")
    return Resolution(uri, Outcome.STATIC, chain, None, "served from disk")
