from __future__ import annotations

from .conftest import hits


def test_if_in_location():
    f = hits("server { location / { if ($a) { add_header X 1; } } }", "NWL070")
    assert "add_header" in f[0].message
    assert hits("server { location / { if ($a) { return 403; } } }", "NWL070") == []
    assert hits("server { if ($a) { add_header X 1; } }", "NWL070") == []


def test_if_host_redirect():
    assert len(hits("server { if ($host = www.a.com) { return 301 https://a.com; } }",
                    "NWL071")) == 1
    assert hits("server { if ($scheme = http) { return 301 https://a.com; } }", "NWL071") == []


def test_if_file_check():
    text = "server { location / { if (!-e $request_filename) { rewrite . /index.php last; } } }"
    assert len(hits(text, "NWL072")) == 1


def test_alias_traversal():
    f = hits("server { location /files { alias /srv/files/; } }", "NWL073")
    assert len(f) == 1 and f[0].line == 1
    assert hits("server { location /files/ { alias /srv/files/; } }", "NWL073") == []
    assert hits("server { location ~ ^/f/(.*)$ { alias /srv/$1; } }", "NWL073") == []


def test_duplicate_server_name():
    text = """
    server { listen 80; server_name a.example.com; }
    server { listen 80; server_name A.example.com b.example.com; }
    server { listen 443 ssl; server_name a.example.com; }
    """
    f = hits(text, "NWL074")
    assert len(f) == 1 and f[0].line == 3
    assert hits("server { server_name _; } server { server_name _; }", "NWL074") == []


def test_root_in_location():
    assert len(hits("server { location / { root /x; } }", "NWL075")) == 1
    assert hits("server { root /y; location / { root /x; } }", "NWL075") == []


def test_include_not_found_ignores_standard_files():
    f = hits("server { include custom.conf; include fastcgi_params; }", "NWL090")
    assert [x.message.split()[1] for x in f] == ["custom.conf"]


def test_parse_error_finding():
    f = hits("server {", "NWL000")
    assert f[0].severity.value == "high"
