from __future__ import annotations

from nginx_wp_lint.rules import Severity

from .conftest import hits, wp

HTTP = """
http {
    server_tokens off;
    %s
    server {
        listen 80;
        server_name c.example.com;
        root /x;
        index index.php;
        location / { try_files $uri $uri/ /index.php?$args; }
        location ~ \\.php$ {
            try_files $uri =404;
            include fastcgi.conf;
            fastcgi_pass php;
            %s
        }
    }
}
"""


def http(http_extra="", php_extra=""):
    return HTTP % (http_extra, php_extra)


def test_permalinks():
    assert hits(wp(), "NWL050") == []
    text = wp().replace("try_files $uri $uri/ /index.php?$args;", "try_files $uri $uri/ =404;")
    f = hits(text, "NWL050")
    assert "fall back to /index.php" in f[0].message
    no_loc = "server { root /x; index index.php; location ~ \\.php$ { fastcgi_pass p; } }"
    assert "no try_files" in hits(no_loc, "NWL050")[0].message
    error_page = ("server { root /x; index index.php; error_page 404 = /index.php; "
                  "location ~ \\.php$ { fastcgi_pass p; } }")
    assert hits(error_page, "NWL050") == []


def test_php_location_file_check():
    assert hits(wp(), "NWL051") == []
    text = wp().replace("try_files $uri =404;", "")
    assert len(hits(text, "NWL051")) == 1
    snippet = text.replace("include fastcgi.conf;", "include snippets/fastcgi-php.conf;")
    assert hits(snippet, "NWL051") == []
    exact = "server { index index.php; location = /wp-login.php { fastcgi_pass p; } }"
    assert hits(exact, "NWL051") == []


def test_script_filename():
    assert hits(wp(), "NWL052") == []
    params = wp().replace("include fastcgi.conf;", "include fastcgi_params;")
    assert len(hits(params, "NWL052")) == 1
    explicit = params.replace(
        "include fastcgi_params;",
        "include fastcgi_params; fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;")
    assert hits(explicit, "NWL052") == []
    unknown = wp().replace("include fastcgi.conf;", "include my-php.conf;")
    assert hits(unknown, "NWL052") == []


def test_wp_login_rate_limit():
    assert len(hits(wp(), "NWL060")) == 1
    limited = wp("location = /wp-login.php { limit_req zone=login; fastcgi_pass p; }")
    assert hits(limited, "NWL060") == []
    server_wide = wp("limit_req zone=all burst=20;")
    assert hits(server_wide, "NWL060") == []


def test_limit_req_zone_undefined():
    text = http("limit_req_zone $binary_remote_addr zone=one:10m rate=1r/s;",
                "limit_req zone=two;")
    f = hits(text, "NWL061")
    assert "'two'" in f[0].message
    ok = http("limit_req_zone $binary_remote_addr zone=one:10m rate=1r/s;", "limit_req zone=one;")
    assert hits(ok, "NWL061") == []
    # Without an http block the zones are unknown: no finding.
    assert hits("server { limit_req zone=x; }", "NWL061") == []


def test_gzip():
    assert len(hits(http(), "NWL020")) == 1
    assert hits(http("gzip on; gzip_types text/css;"), "NWL020") == []
    assert hits(http("brotli on;"), "NWL020") == []
    assert "gzip is off" in hits(http("gzip off;"), "NWL020")[0].message
    assert hits("server { root /x; }", "NWL020")[0].severity is Severity.INFO


def test_gzip_types():
    assert len(hits(http("gzip on;"), "NWL021")) == 1
    assert hits(http("gzip on; gzip_types text/css;"), "NWL021") == []


def test_client_max_body_size():
    assert hits(http(), "NWL022")[0].severity is Severity.LOW
    assert "below 8m" in hits(http("client_max_body_size 2m;"), "NWL022")[0].message
    assert hits(http("client_max_body_size 64m;"), "NWL022") == []
    zero = hits(http("client_max_body_size 0;"), "NWL022")
    assert zero[0].severity is Severity.INFO


def test_fastcgi_cache_rules():
    base_http = ("fastcgi_cache_path /c keys_zone=WP:10m; "
                 'fastcgi_cache_key "$scheme$host$request_uri";')
    good = http(base_http + ' map $http_cookie $skip { default 0; ~wordpress_logged_in 1; }',
                "fastcgi_cache WP; fastcgi_cache_valid 200 1h; fastcgi_cache_bypass $skip; "
                "fastcgi_no_cache $skip;")
    for rule in ("NWL030", "NWL031", "NWL032", "NWL033"):
        assert hits(good, rule) == [], rule
    bad = http("", "fastcgi_cache OTHER;")
    assert len(hits(bad, "NWL030")) == 1
    assert len(hits(bad, "NWL031")) == 1
    assert "not set" in hits(bad, "NWL032")[0].message
    assert len(hits(bad, "NWL033")) == 1
    no_cookie = http(base_http, "fastcgi_cache WP; fastcgi_cache_bypass $a; fastcgi_no_cache $a;")
    f = hits(no_cookie, "NWL032")
    assert f[0].severity is Severity.MEDIUM
    off = http("", "fastcgi_cache off;")
    assert hits(off, "NWL030") == [] and hits(off, "NWL032") == []
