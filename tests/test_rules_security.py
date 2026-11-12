from __future__ import annotations

from nginx_wp_lint.rules import Severity

from .conftest import hits, rule_ids, wp

SECURITY_RULES = ("NWL003", "NWL004", "NWL005", "NWL006", "NWL007", "NWL008", "NWL009")


def test_hardened_wordpress_server_passes_exposure_rules():
    extra = r"""
    location ~* \.(sql|gz|bak|old|save|zip|wpress|log)$|~$ { deny all; }
    location ~* ^/wp-content/(ai1wm-backups|updraft|backups-dup-lite|uploads/wc-logs)/ { deny all; }
    """
    assert rule_ids(wp(extra), only=SECURITY_RULES) == []


def test_server_tokens_http_level():
    f = hits("http { server { listen 80; } }", "NWL001")
    assert len(f) == 1 and f[0].line == 1 and f[0].severity is Severity.LOW
    assert hits("http { server_tokens off; server { listen 80; } }", "NWL001") == []
    f = hits("http { server_tokens off; server { server_tokens on; } }", "NWL001")
    assert "'on'" in f[0].message


def test_server_tokens_fragment_is_info():
    f = hits("server { listen 80; }", "NWL001")
    assert f[0].severity is Severity.INFO
    assert "nginx.conf" in f[0].message


def test_autoindex():
    assert len(hits("server { location /f/ { autoindex on; } }", "NWL002")) == 1
    assert hits("server { autoindex off; }", "NWL002") == []


def test_dotfiles_exposed_and_partial_rule():
    f = hits(wp().replace(r"location ~ /\.(?!well-known/) { deny all; }",
                          r"location ~ /\.git { deny all; }"), "NWL003")
    assert len(f) == 1
    assert "/.env" in f[0].message and "/.git/config" not in f[0].message
    assert hits(wp(), "NWL003") == []


def test_sensitive_files():
    f = hits(wp(), "NWL004")
    assert "/wp-config.php.bak" in f[0].message
    blocked = wp(r"location ~* (\.(sql|gz|bak|old|save|zip|wpress|log)|~)$ { deny all; }")
    assert hits(blocked, "NWL004") == []


def test_sensitive_files_extra_paths_option():
    blocked = wp(r"location ~* (\.(sql|gz|bak|old|save|zip|wpress|log)|~)$ { deny all; }")
    opts = {"client_max_body_size_min": "8m", "hsts_min_max_age": 1,
            "logged_in_cookie": "wordpress_logged_in",
            "extra_sensitive_paths": ["/exports/customers.csv"]}
    f = hits(blocked, "NWL004", options=opts)
    assert "/exports/customers.csv" in f[0].message


def test_wp_config():
    text = wp().replace("location = /wp-config.php { deny all; }", "")
    assert len(hits(text, "NWL005")) == 1
    assert hits(wp(), "NWL005") == []


def test_xmlrpc():
    text = wp().replace("location = /xmlrpc.php { deny all; }", "")
    f = hits(text, "NWL006")
    assert "location ~ \\.php$" in f[0].message
    assert hits(wp(), "NWL006") == []


def test_php_in_uploads_prefix_location_does_not_help():
    text = wp().replace(r"location ~* ^/wp-content/uploads/.*\.php$ { deny all; }",
                        "location /wp-content/uploads/ { expires 30d; }")
    assert len(hits(text, "NWL007")) == 1


def test_php_in_uploads_caret_tilde_protects():
    text = wp().replace(r"location ~* ^/wp-content/uploads/.*\.php$ { deny all; }",
                        "location ^~ /wp-content/uploads/ { expires 30d; }")
    assert hits(text, "NWL007") == []


def test_php_in_uploads_nested_deny():
    text = wp().replace(r"location ~* ^/wp-content/uploads/.*\.php$ { deny all; }",
                        r"location /wp-content/uploads/ { location ~ \.php$ { deny all; } }")
    assert hits(text, "NWL007") == []


def test_php_source_disclosure():
    text = "server { root /x; index index.php; location / { try_files $uri /index.php; } }"
    f = hits(text, "NWL008")
    assert "/wp-config.php" in f[0].message


def test_acme_blocked_by_dot_rule():
    text = wp().replace(r"location ~ /\.(?!well-known/) { deny all; }",
                        r"location ~ /\. { deny all; }")
    assert len(hits(text, "NWL009")) == 1
    assert hits(wp(), "NWL009") == []


def test_redirect_servers_are_skipped():
    text = "server { listen 80; index index.php; return 301 https://$host$request_uri; }"
    assert rule_ids(text, only=SECURITY_RULES) == []


def test_static_site_skips_php_rules():
    text = "server { listen 80; root /var/www; location / { try_files $uri =404; } }"
    assert rule_ids(text, only=SECURITY_RULES) == []
