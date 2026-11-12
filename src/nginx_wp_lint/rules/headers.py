"""Security header rules."""

from __future__ import annotations

import re
from collections.abc import Iterator

from ..headers import HeaderSet, effective_headers, own_add_headers
from ..model import ServerInfo
from .base import Finding, LintContext, Rule, Severity

HSTS = "strict-transport-security"
XCTO = "x-content-type-options"
REFERRER = "referrer-policy"
CSP = "content-security-policy"
CSP_RO = "content-security-policy-report-only"
XFO = "x-frame-options"

SECURITY_HEADERS = (HSTS, XCTO, REFERRER, CSP, CSP_RO, XFO, "permissions-policy")

CANONICAL = {
    HSTS: "Strict-Transport-Security",
    XCTO: "X-Content-Type-Options",
    REFERRER: "Referrer-Policy",
    CSP: "Content-Security-Policy",
    CSP_RO: "Content-Security-Policy-Report-Only",
    XFO: "X-Frame-Options",
    "permissions-policy": "Permissions-Policy",
}


def _server_headers(server: ServerInfo) -> HeaderSet:
    return effective_headers(server.directive)


class _MissingHeader(Rule):
    header = ""
    tls_only = False

    def applies(self, server: ServerInfo, headers: HeaderSet) -> bool:
        return not headers.has(self.header)

    def check(self, ctx: LintContext) -> Iterator[Finding]:
        for server in ctx.content_servers():
            if self.tls_only and not server.is_tls:
                continue
            headers = _server_headers(server)
            if headers.uncertain:
                continue
            if self.applies(server, headers):
                yield self.finding(server.directive, self.message(server, headers),
                                   server=server)

    def message(self, server: ServerInfo, headers: HeaderSet) -> str:
        return f"{CANONICAL[self.header]} header is not set"


class HstsMissing(_MissingHeader):
    id = "NWL010"
    name = "hsts-missing"
    severity = Severity.MEDIUM
    category = "headers"
    summary = "HTTPS server without Strict-Transport-Security"
    hint = ('Add `add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" '
            "always;` once HTTPS works for every subdomain.")
    header = HSTS
    tls_only = True


class HstsWeak(Rule):
    id = "NWL011"
    name = "hsts-weak"
    severity = Severity.LOW
    category = "headers"
    summary = "Strict-Transport-Security max-age is shorter than recommended"
    hint = "Use a max-age of at least 15552000 (180 days); 31536000 (one year) is common."

    def check(self, ctx: LintContext) -> Iterator[Finding]:
        minimum = int(ctx.options.get("hsts_min_max_age", 15552000))
        for server in ctx.content_servers():
            if not server.is_tls:
                continue
            headers = _server_headers(server)
            value = headers.value(HSTS)
            d = headers.get(HSTS)
            if value is None or d is None:
                continue
            m = re.search(r"max-age\s*=\s*\"?(\d+)", value, re.IGNORECASE)
            if not m:
                yield self.finding(d, "Strict-Transport-Security has no max-age",
                                   server=server)
            elif int(m.group(1)) < minimum:
                yield self.finding(d, f"Strict-Transport-Security max-age is {m.group(1)} "
                                      f"seconds (minimum {minimum})", server=server)


class XContentTypeOptionsMissing(_MissingHeader):
    id = "NWL012"
    name = "x-content-type-options-missing"
    severity = Severity.LOW
    category = "headers"
    summary = "X-Content-Type-Options: nosniff is not set"
    hint = "Add `add_header X-Content-Type-Options nosniff always;`"
    header = XCTO


class ReferrerPolicyMissing(_MissingHeader):
    id = "NWL013"
    name = "referrer-policy-missing"
    severity = Severity.LOW
    category = "headers"
    summary = "Referrer-Policy is not set"
    hint = 'Add `add_header Referrer-Policy "strict-origin-when-cross-origin" always;`'
    header = REFERRER


class CspMissing(_MissingHeader):
    id = "NWL014"
    name = "csp-missing"
    severity = Severity.INFO
    category = "headers"
    summary = "No Content-Security-Policy (or Report-Only) header"
    hint = ("Start with a report-only policy and tighten it: "
            "`add_header Content-Security-Policy-Report-Only \"default-src 'self'; ...\" always;`"
            " WordPress plugins often need inline scripts, so test before enforcing.")
    header = CSP

    def applies(self, server, headers):
        return not headers.has(CSP) and not headers.has(CSP_RO)


class AddHeaderInheritance(Rule):
    id = "NWL015"
    name = "add-header-inheritance"
    severity = Severity.MEDIUM
    category = "headers"
    summary = ("A location with its own add_header loses the security headers set at the "
               "server or http level")
    hint = ("Repeat the security headers in this location (an include file helps), use "
            "`add_header_inherit merge;` on nginx 1.29.3+, or move the extra header elsewhere.")

    def check(self, ctx: LintContext) -> Iterator[Finding]:
        for server in ctx.content_servers():
            for loc in server.locations():
                if not own_add_headers(loc):
                    continue
                inherited = effective_headers(loc.parent) if loc.parent else HeaderSet()
                mine = effective_headers(loc)
                lost = [CANONICAL[h] for h in SECURITY_HEADERS
                        if inherited.has(h) and not mine.has(h)]
                if lost:
                    yield self.finding(
                        loc, f"add_header here replaces the inherited headers; responses from "
                             f"this location lose {', '.join(lost)}", server=server)


class ClickjackingProtectionMissing(_MissingHeader):
    id = "NWL016"
    name = "clickjacking-protection-missing"
    severity = Severity.LOW
    category = "headers"
    summary = "Neither X-Frame-Options nor a CSP frame-ancestors directive is set"
    hint = ('Add `add_header X-Frame-Options "SAMEORIGIN" always;` or '
            "`frame-ancestors 'self'` in the Content-Security-Policy.")
    header = XFO

    def applies(self, server, headers):
        if headers.has(XFO):
            return False
        csp = headers.value(CSP) or ""
        return "frame-ancestors" not in csp.lower()

    def message(self, server, headers):
        return "pages can be framed by other sites (no X-Frame-Options or frame-ancestors)"


class HeaderWithoutAlways(Rule):
    id = "NWL017"
    name = "header-without-always"
    severity = Severity.INFO
    category = "headers"
    summary = "Security headers without `always` are missing from error responses"
    hint = "Append `always` to security add_header directives."

    def check(self, ctx: LintContext) -> Iterator[Finding]:
        seen: set[int] = set()
        for d in ctx.named("add_header"):
            if id(d) in seen or d.arg(0).lower() not in SECURITY_HEADERS:
                continue
            seen.add(id(d))
            if "always" not in [a.lower() for a in d.args[2:]]:
                yield self.finding(d, f"{d.arg(0)} is only sent with 2xx/3xx responses; add "
                                      "`always` to include 4xx/5xx pages")


RULES = (HstsMissing, HstsWeak, XContentTypeOptionsMissing, ReferrerPolicyMissing, CspMissing,
         AddHeaderInheritance, ClickjackingProtectionMissing, HeaderWithoutAlways)
