"""Semantic helpers on top of the directive tree: servers, listen sockets,
directive inheritance and size values."""

from __future__ import annotations

import os
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field

from .parser import ROOT, Directive

_SIZE_RE = re.compile(r"^(\d+)([kKmMgG]?)$")


def parse_size(value: str) -> int | None:
    """``8m`` -> bytes. Returns None for values nginx would reject."""
    m = _SIZE_RE.match(value.strip())
    if not m:
        return None
    mult = {"": 1, "k": 1024, "m": 1024 ** 2, "g": 1024 ** 3}[m.group(2).lower()]
    return int(m.group(1)) * mult


_TIME_UNITS = {"ms": 0.001, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800,
               "M": 2592000, "y": 31536000}
_TIME_RE = re.compile(r"(\d+)(ms|s|m|h|d|w|M|y)?")


def parse_time(value: str) -> float | None:
    """nginx time value (``1h30m``, ``60``) -> seconds."""
    text = value.strip()
    if not text:
        return None
    total = 0.0
    pos = 0
    for m in _TIME_RE.finditer(text):
        if m.start() != pos:
            return None
        total += int(m.group(1)) * _TIME_UNITS[m.group(2) or "s"]
        pos = m.end()
    return total if pos == len(text) else None


@dataclass
class Listen:
    directive: Directive | None
    address: str
    port: int | None  # None for unix sockets
    ssl: bool = False
    http2: bool = False
    quic: bool = False
    default_server: bool = False


def parse_listen(d: Directive) -> Listen:
    target = d.arg(0, "80")
    params = {a.lower() for a in d.args[1:]}
    port: int | None
    address = target
    if target.startswith("unix:"):
        port = None
    elif target.startswith("["):
        end = target.find("]")
        rest = target[end + 1:]
        port = int(rest[1:]) if rest.startswith(":") and rest[1:].isdigit() else 80
        address = target[: end + 1]
    elif target.isdigit():
        port = int(target)
        address = "*"
    elif ":" in target:
        host, _, p = target.rpartition(":")
        port = int(p) if p.isdigit() else 80
        address = host
    else:
        port = 80
    return Listen(directive=d, address=address, port=port, ssl="ssl" in params,
                  http2="http2" in params, quic="quic" in params,
                  default_server="default_server" in params or "default" in params)


def directives_at(level: Directive, name: str) -> list[Directive]:
    """Direct children named ``name``, ignoring those inside ``if`` blocks."""
    return [d for d in level.children if d.name == name]


# Standard include files shipped with nginx and Debian/Ubuntu packages. When
# one of them cannot be read (linting a copy of the config on a laptop), its
# content is still known well enough not to make every rule give up.
KNOWN_INCLUDES: dict[str, frozenset[str]] = {
    "fastcgi_params": frozenset({"fastcgi_param"}),
    "fastcgi.conf": frozenset({"fastcgi_param"}),
    "fastcgi-php.conf": frozenset({"fastcgi_split_path_info", "try_files", "set",
                                   "fastcgi_param", "fastcgi_index", "include"}),
    "mime.types": frozenset({"types"}),
    "proxy_params": frozenset({"proxy_set_header"}),
    "uwsgi_params": frozenset({"uwsgi_param"}),
    "scgi_params": frozenset({"scgi_param"}),
    "koi-utf": frozenset({"charset_map"}),
    "koi-win": frozenset({"charset_map"}),
    "win-utf": frozenset({"charset_map"}),
}


def known_include(d: Directive) -> frozenset[str] | None:
    return KNOWN_INCLUDES.get(os.path.basename(d.arg(0)))


def unresolved_includes(level: Directive) -> list[Directive]:
    return [d for d in level.children if d.name == "include" and d.include_resolved is False]


def has_unresolved_include(level: Directive, names: Iterable[str] | None = None) -> bool:
    """True if an include we could not read may set ``names`` (or define
    anything, when ``names`` is None) at this level."""
    wanted = set(names) if names else set()
    for d in unresolved_includes(level):
        known = known_include(d)
        if known is None:
            return True
        if wanted & known:
            return True
    return False


@dataclass
class Effective:
    """The directives that apply at a level after inheritance."""

    directives: list[Directive]
    level: Directive | None  # where they were found
    uncertain: bool = False  # an unresolved include could have set them

    @property
    def found(self) -> bool:
        return bool(self.directives)

    @property
    def last(self) -> Directive | None:
        return self.directives[-1] if self.directives else None


def levels_up(node: Directive) -> Iterator[Directive]:
    """``node`` and its ancestors up to (not including) the root."""
    current: Directive | None = node
    while current is not None and current.name != ROOT:
        if current.name != "if":
            yield current
        current = current.parent


def effective(node: Directive, *names: str) -> Effective:
    """Find the closest level (``node`` first, then its parents) that sets any
    of ``names``. That is how nginx inherits most directives: a level that
    sets a directive replaces the inherited value completely."""
    uncertain = False
    for level in levels_up(node):
        found = [d for d in level.children if d.name in names]
        if found:
            return Effective(found, level, uncertain)
        if has_unresolved_include(level, names):
            uncertain = True
    return Effective([], None, uncertain)


def is_redirect_return(d: Directive) -> bool:
    code = d.arg(0)
    if code.isdigit():
        return 300 <= int(code) < 400
    return code.startswith(("http://", "https://", "$scheme"))


CATCH_ALL_REGEXES = ("^", "^/(.*)$", "^(.*)$", "^/(.*)", "^(.*)", ".*", "^.*$", "^/")


@dataclass
class ServerInfo:
    directive: Directive
    http: Directive | None
    names: list[str] = field(default_factory=list)
    listens: list[Listen] = field(default_factory=list)

    @property
    def label(self) -> str:
        name = next((n for n in self.names if n not in ("_", "")), None)
        ports = sorted({str(listen.port) for listen in self.listens if listen.port})
        port = "/".join(ports)
        return f"{name or '(default)'}:{port}" if port else (name or "(default)")

    @property
    def is_tls(self) -> bool:
        if any(listen.ssl or listen.quic for listen in self.listens):
            return True
        ssl = effective(self.directive, "ssl")
        return bool(ssl.last and ssl.last.arg(0) == "on")

    @property
    def plain_http_listens(self) -> list[Listen]:
        if any(d.name == "ssl" and d.arg(0) == "on" for d in self.directive.children):
            return []
        return [listen for listen in self.listens if not listen.ssl and not listen.quic
                and listen.port is not None]

    @property
    def is_redirect_only(self) -> bool:
        """The server answers every request with a redirect (or error)."""
        for d in self.directive.children:
            if d.name == "return":
                return True
            if d.name == "rewrite" and d.args and d.args[-1] in ("permanent", "redirect") \
                    and d.arg(0) in CATCH_ALL_REGEXES:
                return True
        locations = [d for d in self.directive.children if d.name == "location"]
        catch_all = [loc for loc in locations if loc.args in (["/"], ["~", ".*"])]
        if catch_all and all(any(c.name == "return" for c in loc.children)
                             for loc in catch_all):
            others = [loc for loc in locations if loc not in catch_all]
            return all("acme-challenge" in " ".join(loc.args) for loc in others)
        return False

    @property
    def is_php(self) -> bool:
        for d in self.directive.walk():
            if d.name == "fastcgi_pass":
                return True
            if d.name in ("index", "try_files") and any("index.php" in a for a in d.args):
                return True
            if d.name == "include" and any(
                    "php" in a for a in d.args) and "fastcgi" in " ".join(d.args):
                return True
        return False

    def locations(self) -> list[Directive]:
        return [d for d in self.directive.walk() if d.name == "location"]


def collect_servers(root: Directive) -> list[ServerInfo]:
    servers = []
    for d in root.walk():
        if d.name != "server" or d.block is None:
            continue
        if d.context not in ("http", "main"):
            continue  # stream/mail servers and upstream "server" lines
        if d.context == "main" and not any(c.name in ("listen", "server_name", "location",
                                                      "root") for c in d.children):
            continue
        http = d.enclosing("http")
        names = [a for s in d.find("server_name") for a in s.args]
        listens = [parse_listen(listen) for listen in d.find("listen")]
        if not listens:
            listens = [Listen(directive=None, address="*", port=80)]
        servers.append(ServerInfo(directive=d, http=http, names=names, listens=listens))
    return servers


def iter_named(root: Directive, names: Iterable[str]) -> Iterator[Directive]:
    wanted = set(names)
    for d in root.walk():
        if d.name in wanted:
            yield d
