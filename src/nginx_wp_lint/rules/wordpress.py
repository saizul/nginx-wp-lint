"""WordPress and PHP-FPM rules: permalinks, PHP locations, rate limiting."""

from __future__ import annotations

import os
from collections.abc import Iterator

from ..locations import Outcome, parse_location, resolve
from ..model import effective, levels_up, unresolved_includes
from ..parser import Directive
from .base import Finding, LintContext, Rule, Severity

# Include files known to provide SCRIPT_FILENAME and the "=404" file check.
FASTCGI_FULL_INCLUDES = ("fastcgi.conf", "fastcgi-php.conf")


def _include_names(includes: list[Directive]) -> list[str]:
    return [os.path.basename(d.arg(0)) for d in includes]


def php_locations(ctx: LintContext) -> Iterator[tuple[Directive, object]]:
    for server in ctx.content_servers(php_only=True):
        for loc in server.locations():
            if loc.first("fastcgi_pass") is not None:
                yield loc, server


class PermalinksTryFiles(Rule):
    id = "NWL050"
    name = "permalinks-try-files"
    severity = Severity.MEDIUM
    category = "wordpress"
    summary = "Pretty permalinks are not routed to index.php"
    hint = "In `location /` use `try_files $uri $uri/ /index.php?$args;`"

    def check(self, ctx: LintContext) -> Iterator[Finding]:
        for server in ctx.content_servers(php_only=True):
            res = resolve(server, "/sample-page/")
            if res.outcome is not Outcome.STATIC:
                continue
            node = res.leaf.directive if res.leaf else server.directive
            eff = effective(node, "try_files")
            if eff.found:
                assert eff.last is not None
                if any("index.php" in a for a in eff.last.args):
                    continue
                yield self.finding(eff.last, "try_files does not fall back to /index.php: "
                                             "permalinks such as /sample-page/ return 404",
                                   server=server)
                continue
            if eff.uncertain:
                continue
            error_pages = effective(node, "error_page")
            if any("index.php" in " ".join(d.args) for d in error_pages.directives):
                continue
            yield self.finding(node, "no try_files for permalinks: /sample-page/ returns 404 "
                                     "unless a file with that name exists", server=server)


class PhpLocationNoFileCheck(Rule):
    id = "NWL051"
    name = "php-location-no-file-check"
    severity = Severity.MEDIUM
    category = "wordpress"
    summary = ("The PHP location passes requests for non-existent scripts to PHP-FPM "
               "(path info tricks such as /uploads/image.jpg/x.php)")
    hint = ("Add `try_files $uri =404;` to the PHP location (snippets/fastcgi-php.conf on "
            "Debian/Ubuntu does this), and keep `cgi.fix_pathinfo=0` in php.ini.")

    def check(self, ctx: LintContext) -> Iterator[Finding]:
        for loc, server in php_locations(ctx):
            parsed = parse_location(loc)
            # An exact location only ever serves that one existing script.
            if parsed.modifier == "=" or "php" not in parsed.pattern.lower():
                continue
            eff = effective(loc, "try_files")
            if eff.found and eff.last is not None:
                args = eff.last.args
                if "=404" in args or any("index.php" in a for a in args[-1:]):
                    continue
            if any(c.name == "if" and "-f" in " ".join(c.args) for c in loc.children):
                continue
            includes = unresolved_includes(loc)
            names = _include_names(includes)
            if "fastcgi-php.conf" in names:
                continue
            if any(n not in ("fastcgi_params", "fastcgi.conf") for n in names):
                continue
            yield self.finding(loc, "PHP location has no `try_files $uri =404;`: requests for "
                                    "scripts that do not exist reach PHP-FPM", server=server)


class ScriptFilenameMissing(Rule):
    id = "NWL052"
    name = "script-filename-missing"
    severity = Severity.MEDIUM
    category = "wordpress"
    summary = "fastcgi_pass without SCRIPT_FILENAME: PHP-FPM answers with blank pages"
    hint = ("Use `include fastcgi.conf;` (it sets SCRIPT_FILENAME), or add "
            "`fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;` after "
            "`include fastcgi_params;`.")

    def check(self, ctx: LintContext) -> Iterator[Finding]:
        for loc, server in php_locations(ctx):
            verdict = self._has_script_filename(loc)
            if verdict is False:
                yield self.finding(loc, "no SCRIPT_FILENAME fastcgi_param in scope "
                                        "(fastcgi_params does not set it)", server=server)

    @staticmethod
    def _has_script_filename(loc: Directive) -> bool | None:
        for level in levels_up(loc):
            params = [d for d in level.children if d.name == "fastcgi_param"]
            names = _include_names(unresolved_includes(level))
            if any(n in FASTCGI_FULL_INCLUDES for n in names):
                return True
            if params:
                return any(d.arg(0) == "SCRIPT_FILENAME" for d in params)
            if any(n != "fastcgi_params" for n in names):
                return None
        return False


class WpLoginNoRateLimit(Rule):
    id = "NWL060"
    name = "wp-login-no-rate-limit"
    severity = Severity.MEDIUM
    category = "wordpress"
    summary = "wp-login.php has no limit_req rate limiting (password brute force)"
    hint = ("In the http block: `limit_req_zone $binary_remote_addr zone=wplogin:10m rate=5r/m;` "
            "and in the server: `location = /wp-login.php { limit_req zone=wplogin burst=5 "
            "nodelay; include snippets/fastcgi-php.conf; fastcgi_pass ...; }`")

    def check(self, ctx: LintContext) -> Iterator[Finding]:
        for server in ctx.content_servers(php_only=True):
            res = resolve(server, "/wp-login.php")
            if res.outcome is not Outcome.PHP:
                continue
            node = res.leaf.directive if res.leaf else server.directive
            eff = effective(node, "limit_req")
            if eff.found or eff.uncertain:
                continue
            yield self.finding(server.directive,
                               f"/wp-login.php is handled by {res.describe()} without limit_req",
                               server=server)


class LimitReqZoneUndefined(Rule):
    id = "NWL061"
    name = "limit-req-zone-undefined"
    severity = Severity.HIGH
    category = "wordpress"
    summary = "limit_req uses a zone that no limit_req_zone defines"
    hint = "Define the zone in the http block with `limit_req_zone`."

    def check(self, ctx: LintContext) -> Iterator[Finding]:
        if ctx.fragment:
            return
        zones = set()
        for d in ctx.named("limit_req_zone"):
            for a in d.args:
                if a.startswith("zone="):
                    zones.add(a[5:].split(":", 1)[0])
        for d in ctx.named("limit_req"):
            for a in d.args:
                if a.startswith("zone="):
                    name = a[5:]
                    if name not in zones:
                        yield self.finding(d, f"limit_req zone {name!r} is not defined "
                                              "(nginx -t fails)")


RULES = (PermalinksTryFiles, PhpLocationNoFileCheck, ScriptFilenameMissing, WpLoginNoRateLimit,
         LimitReqZoneUndefined)
