"""Information disclosure and file exposure rules."""

from __future__ import annotations

from collections.abc import Iterator

from ..locations import Outcome, Resolution, resolve
from ..model import ServerInfo, effective
from .base import Finding, LintContext, Rule, Severity


class ServerTokens(Rule):
    id = "NWL001"
    name = "server-tokens"
    severity = Severity.LOW
    category = "security"
    summary = "server_tokens is not off, so every response and error page shows the nginx version"
    hint = "Add `server_tokens off;` to the http block."
    http_level = True

    def check(self, ctx: LintContext) -> Iterator[Finding]:
        reported_http: set[int] = set()
        for server in ctx.servers:
            eff = effective(server.directive, "server_tokens")
            if eff.uncertain and not eff.found:
                continue
            if eff.found:
                d = eff.last
                assert d is not None
                if d.arg(0) != "off":
                    yield self.finding(d, f"server_tokens is {d.arg(0)!r}", server=server,
                                       ctx=ctx)
                continue
            if server.http is not None:
                if id(server.http) not in reported_http:
                    reported_http.add(id(server.http))
                    yield self.finding(server.http, "server_tokens is not set (default: on)",
                                       ctx=ctx)
            else:
                yield self.finding(server.directive, "server_tokens is not set (default: on)",
                                   server=server, ctx=ctx, unset=True)


class AutoindexOn(Rule):
    id = "NWL002"
    name = "autoindex-on"
    severity = Severity.MEDIUM
    category = "security"
    summary = "Directory listings are enabled"
    hint = "Remove `autoindex on;` (the default is off), or limit it to a dedicated location."

    def check(self, ctx: LintContext) -> Iterator[Finding]:
        for d in ctx.named("autoindex"):
            if d.arg(0) == "on":
                yield self.finding(d, "autoindex on lists directory contents, including "
                                      "backups and uploads")


class _ExposureRule(Rule):
    """Resolve test URIs in every PHP server and report the exposed ones."""

    uris: tuple[str, ...] = ()
    bad: tuple[Outcome, ...] = (Outcome.STATIC,)
    php_only = True

    def test_uris(self, ctx: LintContext) -> tuple[str, ...]:
        return self.uris

    def check(self, ctx: LintContext) -> Iterator[Finding]:
        for server in ctx.content_servers(php_only=self.php_only):
            exposed = [r for r in (resolve(server, u) for u in self.test_uris(ctx))
                       if r.outcome in self.bad]
            if exposed:
                yield self.report(ctx, server, exposed)

    def report(self, ctx: LintContext, server: ServerInfo,
               exposed: list[Resolution]) -> Finding:  # pragma: no cover - abstract
        raise NotImplementedError


DOTFILE_URIS = ("/.git/config", "/.env", "/.htaccess", "/.user.ini", "/.svn/entries")


class DotfilesExposed(_ExposureRule):
    id = "NWL003"
    name = "dotfiles-exposed"
    severity = Severity.HIGH
    category = "security"
    summary = "Hidden files such as .git/, .env and .htaccess can be downloaded"
    hint = ("Deny hidden files but keep ACME challenges working: "
            "`location ~ /\\.(?!well-known/) { deny all; }`")
    uris = DOTFILE_URIS
    bad = (Outcome.STATIC, Outcome.PHP)

    def report(self, ctx, server, exposed):
        uris = ", ".join(r.uri for r in exposed)
        return self.finding(server.directive,
                            f"hidden files are served: {uris} (handled by "
                            f"{exposed[0].describe()})", server=server)


BACKUP_URIS = (
    "/wp-config.php.bak",
    "/wp-config.php~",
    "/wp-config.php.save",
    "/wp-config.old",
    "/backup.sql",
    "/database.sql.gz",
    "/site-backup.zip",
    "/backup.tar.gz",
    "/wp-content/debug.log",
    "/wp-content/uploads/wc-logs/fatal-errors-2026-01-01.log",
    "/wp-content/ai1wm-backups/site-20260101.wpress",
    "/wp-content/updraft/backup_2026-01-01-db.gz",
    "/wp-content/backups-dup-lite/site_archive.zip",
)


class SensitiveFilesExposed(_ExposureRule):
    id = "NWL004"
    name = "sensitive-files-exposed"
    severity = Severity.HIGH
    category = "security"
    summary = ("Backups, database dumps, wp-config.php copies and log files are served if "
               "they exist")
    hint = ("Deny them, for example: `location ~* \\.(sql|sql\\.gz|bak|old|orig|save|swp|zip|"
            "tar|tar\\.gz|tgz|gz|wpress|log)$|~$ { deny all; }` and "
            "`location ~* ^/wp-content/(ai1wm-backups|updraft|backups-dup-lite|uploads/wc-logs)/ "
            "{ deny all; }`")
    uris = BACKUP_URIS

    def test_uris(self, ctx):
        extra = tuple(ctx.options.get("extra_sensitive_paths") or ())
        return self.uris + extra

    def report(self, ctx, server, exposed):
        shown = ", ".join(r.uri for r in exposed[:6])
        more = f" and {len(exposed) - 6} more" if len(exposed) > 6 else ""
        return self.finding(server.directive,
                            f"these paths would be downloadable if the files exist: "
                            f"{shown}{more}", server=server)


class WpConfigNotDenied(_ExposureRule):
    id = "NWL005"
    name = "wp-config-not-denied"
    severity = Severity.LOW
    category = "security"
    summary = "Requests for wp-config.php reach PHP"
    hint = "Add `location = /wp-config.php { deny all; }` as defence in depth."
    uris = ("/wp-config.php",)
    bad = (Outcome.PHP,)

    def report(self, ctx, server, exposed):
        return self.finding(server.directive,
                            "/wp-config.php is passed to PHP; nothing is printed today, but a "
                            "PHP-FPM outage or misconfiguration would expose the source",
                            server=server)


class XmlrpcNotBlocked(_ExposureRule):
    id = "NWL006"
    name = "xmlrpc-not-blocked"
    severity = Severity.MEDIUM
    category = "wordpress"
    summary = "xmlrpc.php is reachable (brute force amplification and pingback abuse)"
    hint = ("Block it: `location = /xmlrpc.php { deny all; access_log off; log_not_found off; }`. "
            "Jetpack and some apps need it: allow their addresses before `deny all`.")
    uris = ("/xmlrpc.php",)
    bad = (Outcome.PHP,)

    def report(self, ctx, server, exposed):
        return self.finding(server.directive,
                            f"/xmlrpc.php is executed by PHP (handled by "
                            f"{exposed[0].describe()})", server=server)


class PhpInUploads(_ExposureRule):
    id = "NWL007"
    name = "php-in-uploads"
    severity = Severity.HIGH
    category = "wordpress"
    summary = "PHP files inside wp-content/uploads are executed"
    hint = ("Deny PHP in uploads with a regex location placed BEFORE the PHP location: "
            "`location ~* ^/wp-content/uploads/.*\\.(php|phtml|phar)$ { deny all; }`. "
            "A prefix `location /wp-content/uploads/` does not stop the regex PHP location "
            "unless it uses `^~`.")
    uris = ("/wp-content/uploads/2026/01/shell.php",)
    bad = (Outcome.PHP,)

    def report(self, ctx, server, exposed):
        return self.finding(server.directive,
                            f"an uploaded .php file would run: {exposed[0].uri} is handled "
                            f"by {exposed[0].describe()}", server=server)


class PhpSourceDisclosure(_ExposureRule):
    id = "NWL008"
    name = "php-source-disclosure"
    severity = Severity.HIGH
    category = "wordpress"
    summary = "PHP files are served as plain text instead of being executed"
    hint = ("Add a PHP location, for example `location ~ \\.php$ { include "
            "snippets/fastcgi-php.conf; fastcgi_pass unix:/run/php/php-fpm.sock; }`.")
    uris = ("/wp-config.php", "/index.php", "/wp-login.php")

    def report(self, ctx, server, exposed):
        return self.finding(server.directive,
                            f"{', '.join(r.uri for r in exposed)} would be sent as source code "
                            f"(handled by {exposed[0].describe()}); wp-config.php contains the "
                            "database password", server=server)


class AcmeChallengeBlocked(_ExposureRule):
    id = "NWL009"
    name = "acme-challenge-blocked"
    severity = Severity.LOW
    category = "security"
    summary = "A dotfile rule also blocks /.well-known/acme-challenge/ (certificate renewal)"
    hint = ("Exclude .well-known from the dotfile rule: "
            "`location ~ /\\.(?!well-known/) { deny all; }`")
    uris = ("/.well-known/acme-challenge/token123",)
    bad = (Outcome.DENIED,)
    php_only = False

    def report(self, ctx, server, exposed):
        return self.finding(server.directive,
                            f"/.well-known/acme-challenge/ is denied by "
                            f"{exposed[0].describe()}; HTTP-01 certificate renewal will fail",
                            server=server)


RULES = (ServerTokens, AutoindexOn, DotfilesExposed, SensitiveFilesExposed, WpConfigNotDenied,
         XmlrpcNotBlocked, PhpInUploads, PhpSourceDisclosure, AcmeChallengeBlocked)
