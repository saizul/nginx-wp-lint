from __future__ import annotations

import pytest

from nginx_wp_lint.headers import effective_headers, more_set_header_names
from nginx_wp_lint.model import (
    collect_servers,
    effective,
    parse_listen,
    parse_size,
    parse_time,
)
from nginx_wp_lint.parser import Directive


@pytest.mark.parametrize(("value", "expected"),
                         [("8m", 8 * 1024 ** 2), ("512K", 512 * 1024), ("1g", 1024 ** 3),
                          ("100", 100), ("0", 0), ("8mb", None), ("", None)])
def test_parse_size(value, expected):
    assert parse_size(value) == expected


@pytest.mark.parametrize(("value", "expected"),
                         [("60", 60), ("1h30m", 5400), ("500ms", 0.5), ("1y", 31536000),
                          ("bad", None), ("", None)])
def test_parse_time(value, expected):
    assert parse_time(value) == expected


@pytest.mark.parametrize(
    ("args", "port", "ssl", "http2", "address"),
    [
        (["80"], 80, False, False, "*"),
        (["443", "ssl", "http2"], 443, True, True, "*"),
        (["[::]:443", "ssl"], 443, True, False, "[::]"),
        (["127.0.0.1:8080"], 8080, False, False, "127.0.0.1"),
        (["localhost"], 80, False, False, "localhost"),
        (["unix:/run/nginx.sock"], None, False, False, "unix:/run/nginx.sock"),
        (["443", "quic", "reuseport"], 443, False, False, "*"),
    ],
)
def test_parse_listen(args, port, ssl, http2, address):
    listen = parse_listen(Directive("listen", args, "f", 1))
    assert (listen.port, listen.ssl, listen.http2, listen.address) == (port, ssl, http2,
                                                                       address)


def tree(text):
    from nginx_wp_lint.parser import ROOT, parse_string

    pf = parse_string(text)
    root = Directive(ROOT, [], "t", 0, block=pf.directives)
    for d in pf.directives:
        d.parent = root
    return root


def test_effective_inheritance():
    root = tree("http { gzip on; server { location / { gzip off; } location /a/ { } } }")
    server = root.children[0].children[1]
    loc_off, loc_a = server.find("location")
    assert effective(loc_off, "gzip").last.arg(0) == "off"
    assert effective(loc_a, "gzip").last.arg(0) == "on"
    assert effective(loc_a, "gzip").level.name == "http"
    assert not effective(loc_a, "brotli").found


def test_effective_marks_unknown_include():
    root = tree("http { include extra.conf; server { } }")
    root.children[0].children[0].include_resolved = False
    server = root.children[0].children[1]
    assert effective(server, "gzip").uncertain
    root2 = tree("http { include mime.types; server { } }")
    root2.children[0].children[0].include_resolved = False
    assert not effective(root2.children[0].children[1], "gzip").uncertain


def test_collect_servers_skips_upstream_and_stream():
    root = tree("http { upstream app { server 127.0.0.1:9000; } server { listen 8080; } }\n"
                "stream { server { listen 3306; } }")
    servers = collect_servers(root)
    assert len(servers) == 1
    assert servers[0].listens[0].port == 8080


def test_server_properties():
    root = tree("server { listen 443 ssl; server_name a.example.com; "
                "location / { return 301 https://b.example.com; } }\n"
                "server { server_name c.example.com; ssl on; listen 443; index index.php; }")
    s1, s2 = collect_servers(root)
    assert s1.is_tls and s1.is_redirect_only and not s1.is_php
    assert s1.label == "a.example.com:443"
    assert s2.is_tls and s2.plain_http_listens == [] and s2.is_php


def test_effective_headers_inheritance_and_merge():
    root = tree('server { add_header A 1; add_header B 2; more_set_headers "X-M: y"; '
                "location /a/ { add_header C 3; } "
                "location /b/ { } "
                "location /c/ { add_header_inherit merge; add_header D 4; } }")
    server = root.children[0]
    a, b, c = server.find("location")
    assert set(effective_headers(a).headers) == {"c", "x-m"}
    assert set(effective_headers(b).headers) == {"a", "b", "x-m"}
    assert set(effective_headers(c).headers) == {"a", "b", "d", "x-m"}
    assert effective_headers(b).level is server


def test_more_set_header_names():
    d = Directive("more_set_headers", ["-s", "404", "X-A: 1", "X-B: 2"], "f", 1)
    assert more_set_header_names(d) == ["x-a", "x-b"]
