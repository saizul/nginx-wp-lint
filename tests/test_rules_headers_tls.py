from __future__ import annotations

from .conftest import hits, rule_ids

TLS = """
server {
    listen 443 ssl;
    server_name s.example.com;
    ssl_certificate a; ssl_certificate_key b;
    root /x;
    %s
}
"""

GOOD_HEADERS = """
add_header Strict-Transport-Security "max-age=31536000" always;
add_header X-Content-Type-Options nosniff always;
add_header Referrer-Policy strict-origin-when-cross-origin always;
add_header Content-Security-Policy "default-src 'self'; frame-ancestors 'self'" always;
"""

HEADER_RULES = ("NWL010", "NWL011", "NWL012", "NWL013", "NWL014", "NWL015", "NWL016",
                "NWL017")


def test_all_headers_present():
    assert rule_ids(TLS % GOOD_HEADERS, only=HEADER_RULES) == []


def test_missing_headers():
    assert rule_ids(TLS % "", only=HEADER_RULES) == ["NWL010", "NWL012", "NWL013", "NWL014",
                                                     "NWL016"]


def test_hsts_only_for_tls():
    text = "server { listen 80; root /x; }"
    assert "NWL010" not in rule_ids(text, only=HEADER_RULES)


def test_hsts_weak():
    f = hits(TLS % 'add_header Strict-Transport-Security "max-age=600" always;', "NWL011")
    assert "600" in f[0].message
    f = hits(TLS % 'add_header Strict-Transport-Security "includeSubDomains" always;', "NWL011")
    assert "no max-age" in f[0].message


def test_csp_report_only_counts():
    text = TLS % 'add_header Content-Security-Policy-Report-Only "default-src *" always;'
    assert hits(text, "NWL014") == []


def test_x_frame_options_or_frame_ancestors():
    assert hits(TLS % "add_header X-Frame-Options DENY always;", "NWL016") == []
    assert len(hits(TLS % 'add_header Content-Security-Policy "default-src *" always;',
                    "NWL016")) == 1


def test_add_header_inheritance():
    text = TLS % (GOOD_HEADERS + 'location ~* \\.css$ { add_header Cache-Control "max-age=1"; }')
    f = hits(text, "NWL015")
    assert len(f) == 1
    assert "Strict-Transport-Security" in f[0].message
    merged = TLS % (GOOD_HEADERS + "location /m/ { add_header_inherit merge; add_header X 1; }")
    assert hits(merged, "NWL015") == []


def test_headers_from_http_level_are_inherited():
    text = "http { " + GOOD_HEADERS + " server { listen 443 ssl; root /x; } }"
    assert rule_ids(text, only=HEADER_RULES) == []


def test_unresolved_include_suppresses_missing_header_rules():
    text = TLS % "include snippets/headers.conf;"
    assert rule_ids(text, only=("NWL010", "NWL012", "NWL013")) == []


def test_header_without_always():
    f = hits(TLS % "add_header X-Content-Type-Options nosniff;", "NWL017")
    assert len(f) == 1
    assert hits(TLS % "add_header X-Custom yes;", "NWL017") == []


def test_more_set_headers_count():
    text = TLS % 'more_set_headers "Strict-Transport-Security: max-age=31536000";'
    assert "NWL010" not in rule_ids(text, only=HEADER_RULES)


def test_weak_protocols_and_ciphers():
    assert len(hits("ssl_protocols TLSv1 TLSv1.2;", "NWL040")) == 1
    assert hits("ssl_protocols TLSv1.2 TLSv1.3;", "NWL040") == []
    f = hits("ssl_ciphers HIGH:!aNULL:!MD5:RC4-SHA:DES-CBC3-SHA;", "NWL041")
    assert "RC4-SHA" in f[0].message and "!MD5" not in f[0].message
    assert hits("ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-CHACHA20-POLY1305;",
                "NWL041") == []
    assert len(hits("ssl_ciphers ALL;", "NWL041")) == 1


def test_ssl_on_and_http2_listen():
    assert len(hits("server { ssl on; }", "NWL042")) == 1
    assert len(hits("server { listen 443 ssl http2; }", "NWL043")) == 1
    assert hits("server { listen 443 ssl; http2 on; }", "NWL043") == []


def test_listen_443_without_ssl():
    assert len(hits("server { listen 443; ssl_certificate a; }", "NWL045")) == 1
    assert hits("server { listen 443 ssl; }", "NWL045") == []
    assert hits("server { listen 443; ssl on; }", "NWL045") == []


def test_https_redirect_missing():
    text = """
    server { listen 80; server_name a.example.com; root /x; }
    server { listen 443 ssl; server_name a.example.com; root /x; }
    """
    assert len(hits(text, "NWL044")) == 1
    redirect = """
    server { listen 80; server_name a.example.com; return 301 https://$host$request_uri; }
    server { listen 443 ssl; server_name a.example.com; root /x; }
    """
    assert hits(redirect, "NWL044") == []
    combined = """
    server { listen 80; listen 443 ssl; server_name a.example.com; root /x;
             if ($scheme = http) { return 301 https://$host$request_uri; } }
    """
    assert hits(combined, "NWL044") == []
    http_only = "server { listen 80; server_name only-http.example.com; root /x; }"
    assert hits(http_only, "NWL044") == []


def test_ssl_protocols_unset():
    f = hits("server { listen 443 ssl; root /x; }", "NWL046")
    assert len(f) == 1
    assert hits("http { ssl_protocols TLSv1.2; server { listen 443 ssl; } }", "NWL046") == []
