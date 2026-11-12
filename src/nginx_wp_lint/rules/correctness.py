"""Configuration pitfalls: `if`, alias traversal, duplicate names, includes."""

from __future__ import annotations

from collections.abc import Iterator

from ..locations import parse_location
from ..model import known_include
from .base import Finding, LintContext, Rule, Severity

SAFE_IN_IF = frozenset({"return", "rewrite", "set", "break"})


class ParseErrorRule(Rule):
    id = "NWL000"
    name = "parse-error"
    severity = Severity.HIGH
    category = "syntax"
    summary = "The file could not be read or parsed"
    hint = "Fix the syntax error; `nginx -t` shows the same problem."

    def check(self, ctx: LintContext) -> Iterator[Finding]:
        return iter(())  # reported by the linter itself


class IfInLocation(Rule):
    id = "NWL070"
    name = "if-in-location"
    severity = Severity.MEDIUM
    category = "correctness"
    summary = "`if` inside a location does more than return or rewrite (\"if is evil\")"
    hint = ("Inside a location, only use `return` and `rewrite ... last` in an `if`. Use "
            "try_files, map or separate locations for the rest.")

    def check(self, ctx: LintContext) -> Iterator[Finding]:
        for d in ctx.named("if"):
            parent = d.parent
            if parent is None or parent.name != "location":
                continue
            unsafe = sorted({c.name for c in d.children if c.name not in SAFE_IN_IF})
            if unsafe:
                yield self.finding(d, f"`if` in a location with {', '.join(unsafe)}: these "
                                      "behave unpredictably inside if")


class IfHostRedirect(Rule):
    id = "NWL071"
    name = "if-host-redirect"
    severity = Severity.INFO
    category = "correctness"
    summary = "Redirecting by testing $host in an `if`"
    hint = ("Use a separate server block for the other name: `server { server_name "
            "www.example.com; return 301 https://example.com$request_uri; }`")

    def check(self, ctx: LintContext) -> Iterator[Finding]:
        for d in ctx.named("if"):
            if d.parent is None or d.parent.name != "server":
                continue
            cond = " ".join(d.args)
            if ("$host" in cond or "$http_host" in cond) and any(
                    c.name in ("return", "rewrite") for c in d.children):
                yield self.finding(d, "host based redirect with `if`; a dedicated server block "
                                      "is evaluated once and is clearer")


class IfFileCheck(Rule):
    id = "NWL072"
    name = "if-file-check"
    severity = Severity.LOW
    category = "correctness"
    summary = "File existence check with `if` and rewrite instead of try_files"
    hint = "Replace with `try_files $uri $uri/ /index.php?$args;`"

    def check(self, ctx: LintContext) -> Iterator[Finding]:
        for d in ctx.named("if"):
            cond = " ".join(d.args)
            if any(op in cond for op in ("-f", "-e", "-d")) and "$request_filename" in cond \
                    and any(c.name == "rewrite" for c in d.children):
                yield self.finding(d, "`if (!-e $request_filename) { rewrite ... }` is the old "
                                      "Apache-style pattern; try_files is faster and safer")


class AliasTraversal(Rule):
    id = "NWL073"
    name = "alias-traversal"
    severity = Severity.HIGH
    category = "security"
    summary = "Prefix location without a trailing slash uses an alias with one (path traversal)"
    hint = ("Make both end with a slash: `location /files/ { alias /srv/files/; }` "
            "(or use root).")

    def check(self, ctx: LintContext) -> Iterator[Finding]:
        for d in ctx.named("location"):
            loc = parse_location(d)
            if loc.modifier not in ("", "^~") or loc.pattern.endswith("/"):
                continue
            for alias in d.find("alias"):
                if alias.arg(0).endswith("/"):
                    yield self.finding(alias, f"`location {loc.pattern}` with `alias "
                                              f"{alias.arg(0)}` lets {loc.pattern}../ escape "
                                              "the directory")


class DuplicateServerName(Rule):
    id = "NWL074"
    name = "duplicate-server-name"
    severity = Severity.MEDIUM
    category = "correctness"
    summary = "The same server_name is used by two servers on the same port"
    hint = "Merge the server blocks or remove the name from one of them."

    def check(self, ctx: LintContext) -> Iterator[Finding]:
        seen: dict[tuple[str, int], object] = {}
        for s in ctx.servers:
            names_dir = s.directive.first("server_name")
            if names_dir is None:
                continue
            ports = sorted({listen.port for listen in s.listens if listen.port is not None})
            for name in s.names:
                if name in ("_", "") or name.startswith("~"):
                    continue
                for port in ports:
                    key = (name.lower(), port)
                    if key in seen:
                        first = seen[key]
                        where = first.directive.location_text()  # type: ignore[attr-defined]
                        yield self.finding(names_dir, f"server_name {name} on port {port} is "
                                                      f"already used at {where}; nginx ignores "
                                                      "this one", server=s)
                    else:
                        seen[key] = s


class RootInLocation(Rule):
    id = "NWL075"
    name = "root-in-location"
    severity = Severity.INFO
    category = "correctness"
    summary = "root is set inside locations but not in the server block"
    hint = "Set root once in the server block; locations inherit it."

    def check(self, ctx: LintContext) -> Iterator[Finding]:
        for s in ctx.content_servers():
            if s.directive.first("root") is not None:
                continue
            roots = [d for loc in s.locations() for d in loc.find("root")]
            if roots:
                yield self.finding(roots[0], "root only inside locations: requests that match "
                                             "no location use the compiled-in default html "
                                             "directory", server=s)


class IncludeNotFound(Rule):
    id = "NWL090"
    name = "include-not-found"
    severity = Severity.INFO
    category = "syntax"
    summary = "An include matched no file, so rules that depend on it were skipped"
    hint = "Lint on the server, pass --prefix /etc/nginx, or copy the snippets into the repo."

    def check(self, ctx: LintContext) -> Iterator[Finding]:
        for d in ctx.config.missing_includes:
            if known_include(d) is not None:
                continue  # standard file, its content is known
            yield self.finding(d, f"include {d.arg(0)} not found; checks that need its content "
                                  "assume nothing")


RULES = (ParseErrorRule, IfInLocation, IfHostRedirect, IfFileCheck, AliasTraversal,
         DuplicateServerName, RootInLocation, IncludeNotFound)
