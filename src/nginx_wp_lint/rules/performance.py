"""Compression, upload size and FastCGI cache rules."""

from __future__ import annotations

from collections.abc import Iterator

from ..headers import effective_headers
from ..locations import Outcome, resolve
from ..model import effective, parse_size
from ..parser import Directive
from .base import Finding, LintContext, Rule, Severity


class GzipDisabled(Rule):
    id = "NWL020"
    name = "gzip-disabled"
    severity = Severity.LOW
    category = "performance"
    summary = "Neither gzip nor brotli compression is enabled"
    hint = "Add `gzip on;` with `gzip_types` (and `brotli on;` if the module is installed)."
    http_level = True

    def check(self, ctx: LintContext) -> Iterator[Finding]:
        reported_http: set[int] = set()
        for server in ctx.content_servers():
            gzip = effective(server.directive, "gzip")
            brotli = effective(server.directive, "brotli")
            if (gzip.last and gzip.last.arg(0) == "on") or (
                    brotli.last and brotli.last.arg(0) == "on"):
                continue
            if gzip.uncertain or brotli.uncertain:
                continue
            if gzip.found:
                assert gzip.last is not None
                yield self.finding(gzip.last, "gzip is off and brotli is not enabled",
                                   server=server)
            elif server.http is not None:
                if id(server.http) not in reported_http:
                    reported_http.add(id(server.http))
                    yield self.finding(server.http, "compression is not enabled "
                                                    "(gzip defaults to off)")
            else:
                yield self.finding(server.directive, "compression is not enabled "
                                                     "(gzip defaults to off)",
                                   server=server, ctx=ctx, unset=True)


class GzipTypesDefault(Rule):
    id = "NWL021"
    name = "gzip-types-default"
    severity = Severity.LOW
    category = "performance"
    summary = "gzip is on but gzip_types is not set, so only text/html is compressed"
    hint = ("Add `gzip_types text/css application/javascript application/json image/svg+xml "
            "text/plain text/xml application/xml;`")

    def check(self, ctx: LintContext) -> Iterator[Finding]:
        seen: set[int] = set()
        for d in ctx.named("gzip"):
            if d.arg(0) != "on" or id(d) in seen:
                continue
            seen.add(id(d))
            parent = d.parent
            if parent is None:
                continue
            types = effective(parent, "gzip_types")
            if not types.found and not types.uncertain:
                # A lower level may still set gzip_types for its own scope.
                lower = any(c.name == "gzip_types" for c in parent.walk())
                if not lower:
                    yield self.finding(d, "gzip_types is not set: CSS, JavaScript, JSON and "
                                          "SVG are sent uncompressed")


class ClientMaxBodySize(Rule):
    id = "NWL022"
    name = "client-max-body-size"
    severity = Severity.LOW
    category = "wordpress"
    summary = "client_max_body_size is missing (1 MB default), too small, or unlimited"
    hint = "Set `client_max_body_size 64m;` (match upload_max_filesize in php.ini)."
    http_level = True

    def check(self, ctx: LintContext) -> Iterator[Finding]:
        minimum_text = str(ctx.options.get("client_max_body_size_min", "8m"))
        minimum = parse_size(minimum_text) or 8 * 1024 * 1024
        for server in ctx.content_servers(php_only=True):
            eff = effective(server.directive, "client_max_body_size")
            if not eff.found:
                if eff.uncertain:
                    continue
                yield self.finding(server.directive,
                                   "client_max_body_size is not set: uploads over 1 MB fail "
                                   "with 413 Request Entity Too Large",
                                   server=server, ctx=ctx, unset=True)
                continue
            d = eff.last
            assert d is not None
            size = parse_size(d.arg(0))
            if size is None:
                continue
            if size == 0:
                yield self.finding(d, "client_max_body_size 0 disables the request size limit",
                                   severity=Severity.INFO, server=server,
                                   hint="Set an explicit limit such as 64m or 128m.")
            elif size < minimum:
                yield self.finding(d, f"client_max_body_size {d.arg(0)} is below "
                                      f"{minimum_text}; media and plugin uploads will fail",
                                   server=server)


# Typical WordPress static files: theme CSS, core JavaScript and an uploaded image.
STATIC_PROBES = (
    ("CSS", "/wp-content/themes/theme/style.css"),
    ("JavaScript", "/wp-includes/js/jquery/jquery.min.js"),
    ("images", "/wp-content/uploads/2026/01/photo.jpg"),
)


def _caches(node: Directive) -> bool | None:
    """True if responses at ``node`` get a cache lifetime, None if an include may set one."""
    expires = effective(node, "expires")
    if expires.found:
        assert expires.last is not None
        return expires.last.arg(0).lower() not in ("off", "epoch")
    headers = effective_headers(node)
    if headers.has("cache-control") or headers.has("expires"):
        return True
    if expires.uncertain or headers.uncertain:
        return None
    return False


class StaticAssetsNoCache(Rule):
    id = "NWL023"
    name = "static-assets-no-cache"
    severity = Severity.LOW
    category = "performance"
    summary = ("CSS, JavaScript and images are served without a cache lifetime "
               "(expires or Cache-Control)")
    hint = ("Add a static files location, e.g. `location ~* "
            "\\.(?:css|js|mjs|jpe?g|png|gif|webp|avif|svg|ico|woff2?)$ "
            "{ expires 30d; access_log off; try_files $uri =404; }`")

    def check(self, ctx: LintContext) -> Iterator[Finding]:
        for server in ctx.content_servers(php_only=True):
            missing: list[str] = []
            anchor: Directive | None = None
            where = "the server block"
            for label, uri in STATIC_PROBES:
                res = resolve(server, uri)
                if res.outcome is not Outcome.STATIC:
                    continue
                node = res.leaf.directive if res.leaf else server.directive
                if _caches(node) is False:
                    missing.append(label)
                    if anchor is None:
                        anchor = node
                        if res.leaf is not None:
                            where = f"{res.leaf} at line {node.line}"
            if missing and anchor is not None:
                kinds = missing[0] if len(missing) == 1 else (
                    f"{', '.join(missing[:-1])} and {missing[-1]}")
                yield self.finding(anchor, f"{kinds} are served without expires or "
                                           f"Cache-Control ({where}), so browsers revalidate them "
                                           "on every page view", server=server)


def _zone_names(ctx: LintContext, directive: str, key: str) -> set[str]:
    names = set()
    for d in ctx.named(directive):
        for arg in d.args:
            if arg.startswith(key + "="):
                names.add(arg.split("=", 1)[1].split(":", 1)[0])
    return names


def _cache_users(ctx: LintContext) -> list[Directive]:
    return [d for d in ctx.named("fastcgi_cache")
            if d.args and d.arg(0) != "off" and d.context in ("http", "server", "location")]


class FastcgiCacheZoneUndefined(Rule):
    id = "NWL030"
    name = "fastcgi-cache-zone-undefined"
    severity = Severity.HIGH
    category = "cache"
    summary = "fastcgi_cache names a zone that no fastcgi_cache_path defines"
    hint = ("Define it in the http block: `fastcgi_cache_path /var/cache/nginx/wp levels=1:2 "
            "keys_zone=WORDPRESS:100m inactive=60m;`")

    def check(self, ctx: LintContext) -> Iterator[Finding]:
        if ctx.fragment:
            return
        zones = _zone_names(ctx, "fastcgi_cache_path", "keys_zone")
        for d in _cache_users(ctx):
            name = d.arg(0)
            if "$" in name or name in zones:
                continue
            yield self.finding(d, f"cache zone {name!r} is not defined by any "
                                  "fastcgi_cache_path (nginx -t fails)")


class FastcgiCacheKeyMissing(Rule):
    id = "NWL031"
    name = "fastcgi-cache-key-missing"
    severity = Severity.HIGH
    category = "cache"
    summary = "fastcgi_cache is used without fastcgi_cache_key"
    hint = 'Add `fastcgi_cache_key "$scheme$request_method$host$request_uri";`'
    http_level = True

    def check(self, ctx: LintContext) -> Iterator[Finding]:
        for d in _cache_users(ctx):
            assert d.parent is not None
            eff = effective(d.parent, "fastcgi_cache_key")
            if eff.found or eff.uncertain:
                continue
            yield self.finding(d, "no fastcgi_cache_key in scope; without a key that includes "
                                  "$host and $request_uri, pages are mixed up between sites",
                               ctx=ctx, unset=True)


COOKIE_HINT = ('set $skip_cache 0; if ($http_cookie ~* "comment_author|wordpress_[a-f0-9]+|'
               'wp-postpass|wordpress_no_cache|wordpress_logged_in|woocommerce_items_in_cart") '
               "{ set $skip_cache 1; } fastcgi_cache_bypass $skip_cache; "
               "fastcgi_no_cache $skip_cache;")


class FastcgiCacheNoBypass(Rule):
    id = "NWL032"
    name = "fastcgi-cache-no-bypass"
    severity = Severity.HIGH
    category = "cache"
    summary = ("FastCGI cache without a bypass for logged-in users, carts and POST requests: "
               "private pages can be cached and shown to visitors")
    hint = f"Skip the cache for logged-in users and carts, for example: `{COOKIE_HINT}`"

    def check(self, ctx: LintContext) -> Iterator[Finding]:
        cookie = str(ctx.options.get("logged_in_cookie", "wordpress_logged_in"))
        mentions_cookie = any(cookie in a or "wordpress_[" in a
                              for d in ctx.walk() for a in [d.name, *d.args])
        for d in _cache_users(ctx):
            assert d.parent is not None
            bypass = effective(d.parent, "fastcgi_cache_bypass")
            nocache = effective(d.parent, "fastcgi_no_cache")
            if (bypass.uncertain and not bypass.found) or (nocache.uncertain
                                                           and not nocache.found):
                continue
            missing = [name for name, eff in (("fastcgi_cache_bypass", bypass),
                                              ("fastcgi_no_cache", nocache)) if not eff.found]
            if missing:
                yield self.finding(d, f"{' and '.join(missing)} not set: responses for "
                                      "logged-in users can be cached and served to everyone")
            elif not mentions_cookie:
                yield self.finding(d, f"cache bypass never checks the {cookie} cookie; "
                                      "make sure logged-in users skip the cache",
                                   severity=Severity.MEDIUM)


class FastcgiCacheValidMissing(Rule):
    id = "NWL033"
    name = "fastcgi-cache-valid-missing"
    severity = Severity.INFO
    category = "cache"
    summary = "fastcgi_cache without fastcgi_cache_valid caches only responses with cache headers"
    hint = ("Add `fastcgi_cache_valid 200 301 302 60m;` (and "
            "`fastcgi_cache_use_stale error timeout updating;`).")

    def check(self, ctx: LintContext) -> Iterator[Finding]:
        for d in _cache_users(ctx):
            assert d.parent is not None
            eff = effective(d.parent, "fastcgi_cache_valid")
            if not eff.found and not eff.uncertain:
                yield self.finding(d, "fastcgi_cache_valid is not set; WordPress pages without "
                                      "Cache-Control/Expires headers are not cached")


RULES = (GzipDisabled, GzipTypesDefault, ClientMaxBodySize, StaticAssetsNoCache,
         FastcgiCacheZoneUndefined, FastcgiCacheKeyMissing, FastcgiCacheNoBypass,
         FastcgiCacheValidMissing)
