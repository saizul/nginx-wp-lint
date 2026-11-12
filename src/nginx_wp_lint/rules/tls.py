"""TLS and HTTPS rules."""

from __future__ import annotations

from collections.abc import Iterator

from ..model import ServerInfo, effective, is_redirect_return
from .base import Finding, LintContext, Rule, Severity

WEAK_PROTOCOLS = ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1")
WEAK_CIPHER_TOKENS = ("RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "EXP", "ANULL", "ENULL",
                      "ADH", "AECDH", "LOW", "RC2")


class WeakSslProtocols(Rule):
    id = "NWL040"
    name = "weak-ssl-protocols"
    severity = Severity.HIGH
    category = "tls"
    summary = "ssl_protocols enables SSLv2, SSLv3, TLSv1 or TLSv1.1"
    hint = "Use `ssl_protocols TLSv1.2 TLSv1.3;`"

    def check(self, ctx: LintContext) -> Iterator[Finding]:
        for d in ctx.named("ssl_protocols"):
            weak = [p for p in d.args if p in WEAK_PROTOCOLS]
            if weak:
                yield self.finding(d, f"deprecated protocols enabled: {', '.join(weak)}")


def weak_cipher_parts(spec: str) -> list[str]:
    weak = []
    for part in spec.replace(",", ":").replace(" ", ":").split(":"):
        token = part.strip()
        if not token or token[0] in "!-":
            continue
        upper = token.lstrip("+").upper()
        pieces = set(upper.replace("_", "-").split("-"))
        if upper in ("ALL", "COMPLEMENTOFALL", "MEDIUM", "LOW", "EXPORT", "EXP") or pieces & {
                t.upper() for t in WEAK_CIPHER_TOKENS} or "DES-CBC3" in upper:
            weak.append(token)
    return weak


class WeakSslCiphers(Rule):
    id = "NWL041"
    name = "weak-ssl-ciphers"
    severity = Severity.MEDIUM
    category = "tls"
    summary = "ssl_ciphers allows broken or weak ciphers (RC4, DES/3DES, MD5, NULL, EXPORT ...)"
    hint = ("Use a current profile such as Mozilla's intermediate configuration, e.g. "
            "`ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
            "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
            "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;`")

    def check(self, ctx: LintContext) -> Iterator[Finding]:
        for d in ctx.named("ssl_ciphers"):
            weak = weak_cipher_parts(" ".join(d.args))
            if weak:
                shown = ", ".join(weak[:5]) + (" ..." if len(weak) > 5 else "")
                yield self.finding(d, f"weak cipher selections: {shown}")


class SslDirectiveRemoved(Rule):
    id = "NWL042"
    name = "ssl-directive-removed"
    severity = Severity.MEDIUM
    category = "tls"
    summary = "`ssl on;` was removed in nginx 1.25.1"
    hint = "Delete `ssl on;` and use `listen 443 ssl;`."

    def check(self, ctx: LintContext) -> Iterator[Finding]:
        for d in ctx.named("ssl"):
            if d.context in ("http", "server") and d.arg(0) in ("on", "off"):
                yield self.finding(d, f"`ssl {d.arg(0)};` is obsolete (deprecated since 1.15.0, "
                                      "removed in 1.25.1): nginx -t fails on current versions")


class ListenHttp2Deprecated(Rule):
    id = "NWL043"
    name = "listen-http2-deprecated"
    severity = Severity.INFO
    category = "tls"
    summary = "The http2 parameter of listen is deprecated since nginx 1.25.1"
    hint = "Use `listen 443 ssl;` plus `http2 on;` on nginx 1.25.1 and later."

    def check(self, ctx: LintContext) -> Iterator[Finding]:
        for d in ctx.named("listen"):
            if "http2" in d.args[1:]:
                yield self.finding(d, "`listen ... http2` is deprecated; use the `http2 on;` "
                                      "directive")


def _redirects_on_http(server: ServerInfo) -> bool:
    """A server listening on both ports that redirects plain HTTP itself."""
    for d in server.directive.children:
        if d.name != "if":
            continue
        cond = " ".join(d.args).replace(" ", "")
        if any(k in cond for k in ("$scheme=http", "$scheme=\"http\"", "$https=\"\"", "$https=''",
                                   "$https!=on", "$https!=\"on\"", "$server_port=80",
                                   "$server_port=\"80\"", "$scheme!=https",
                                   "$scheme!=\"https\"")):
            if any(c.name == "return" and is_redirect_return(c) for c in d.children):
                return True
            if any(c.name == "rewrite" and c.args and c.args[-1] in ("permanent", "redirect")
                   for c in d.children):
                return True
    return False


class HttpsRedirectMissing(Rule):
    id = "NWL044"
    name = "https-redirect-missing"
    severity = Severity.MEDIUM
    category = "tls"
    summary = "A site is available over HTTPS but plain HTTP is served instead of redirected"
    hint = ("Add a port 80 server that only redirects: `server { listen 80; listen [::]:80; "
            "server_name example.com; return 301 https://$host$request_uri; }`")

    def check(self, ctx: LintContext) -> Iterator[Finding]:
        tls_names = set()
        for s in ctx.servers:
            if s.is_tls:
                tls_names.update(n for n in s.names if n not in ("_", ""))
        for s in ctx.servers:
            if not s.plain_http_listens or s.is_redirect_only:
                continue
            names = [n for n in s.names if n not in ("_", "")]
            overlap = sorted(set(names) & tls_names)
            if not overlap:
                continue
            if _redirects_on_http(s):
                continue
            ports = ", ".join(str(listen.port) for listen in s.plain_http_listens)
            yield self.finding(s.directive,
                               f"{overlap[0]} has an HTTPS server, but requests on port {ports} "
                               "are served over plain HTTP", server=s)


class Listen443WithoutSsl(Rule):
    id = "NWL045"
    name = "listen-443-without-ssl"
    severity = Severity.HIGH
    category = "tls"
    summary = "listen 443 without the ssl parameter speaks plain HTTP on the HTTPS port"
    hint = "Use `listen 443 ssl;` (and `listen [::]:443 ssl;`)."

    def check(self, ctx: LintContext) -> Iterator[Finding]:
        for s in ctx.servers:
            if any(d.name == "ssl" and d.arg(0) == "on" for d in s.directive.children):
                continue
            for listen in s.listens:
                if listen.port == 443 and not listen.ssl and not listen.quic \
                        and listen.directive is not None:
                    yield self.finding(listen.directive,
                                       "port 443 without `ssl`: browsers get a protocol error",
                                       server=s)


class SslProtocolsUnset(Rule):
    id = "NWL046"
    name = "ssl-protocols-unset"
    severity = Severity.INFO
    category = "tls"
    summary = "HTTPS server relies on the default ssl_protocols"
    hint = "Set `ssl_protocols TLSv1.2 TLSv1.3;` explicitly in the http block."
    http_level = True

    def check(self, ctx: LintContext) -> Iterator[Finding]:
        for s in ctx.servers:
            if not s.is_tls:
                continue
            eff = effective(s.directive, "ssl_protocols")
            if not eff.found and not eff.uncertain:
                yield self.finding(s.directive, "ssl_protocols is not set; older nginx "
                                                "versions enable TLSv1 and TLSv1.1 by default",
                                   server=s, ctx=ctx, unset=True)


RULES = (WeakSslProtocols, WeakSslCiphers, SslDirectiveRemoved, ListenHttp2Deprecated,
         HttpsRedirectMissing, Listen443WithoutSsl, SslProtocolsUnset)
