from __future__ import annotations

import textwrap

import pytest

from nginx_wp_lint.locations import (
    Outcome,
    evaluate_if,
    find_location,
    parse_location,
    pcre_to_python,
    resolve,
)
from nginx_wp_lint.parser import ROOT, Directive, parse_string


def server(text: str) -> Directive:
    pf = parse_string(textwrap.dedent(text))
    root = Directive(ROOT, [], "t", 0, block=pf.directives)
    for d in pf.directives:
        d.parent = root
    return pf.directives[0]


def chain(srv: Directive, uri: str) -> list[str]:
    return [" ".join(loc.directive.args) for loc in find_location(srv, uri)]


SRV = server(r"""
server {
    location = / { return 200; }
    location / { }
    location /images/ {
        location ~ \.php$ { deny all; }
    }
    location ^~ /static/ { }
    location ~* \.(gif|jpg)$ { }
    location ~ \.php$ { fastcgi_pass x; }
    location /documents/ { }
    location @fallback { }
}
""")


@pytest.mark.parametrize(
    ("uri", "expected"),
    [
        ("/", ["= /"]),
        ("/index.html", ["/"]),
        ("/documents/a.html", ["/documents/"]),
        ("/documents/a.jpg", ["~* \\.(gif|jpg)$"]),  # regex beats a plain prefix
        ("/static/a.jpg", ["^~ /static/"]),  # ^~ stops the regex search
        ("/images/a.php", ["/images/", "~ \\.php$"]),  # nested regex wins first
        ("/images/a.JPG", ["~* \\.(gif|jpg)$"]),
        ("/x.php", ["~ \\.php$"]),
    ],
)
def test_location_selection(uri, expected):
    assert chain(SRV, uri) == expected


def test_named_locations_never_match():
    assert all("@" not in c for c in chain(SRV, "/@fallback"))


def test_no_match():
    srv = server("server { location /a/ { } }")
    assert find_location(srv, "/b") == []


@pytest.mark.parametrize(
    ("args", "modifier", "pattern"),
    [
        (["/"], "", "/"),
        (["=", "/x"], "=", "/x"),
        (["=/x"], "=", "/x"),
        (["^~", "/s/"], "^~", "/s/"),
        (["~*\\.jpg$"], "~*", "\\.jpg$"),
        (["~", "\\.php$"], "~", "\\.php$"),
        (["@named"], "@", "named"),
    ],
)
def test_parse_location(args, modifier, pattern):
    loc = parse_location(Directive("location", args, "f", 1, block=[]))
    assert (loc.modifier, loc.pattern) == (modifier, pattern)


def test_pcre_named_groups_and_bad_regex():
    assert pcre_to_python("(?<year>\\d{4})") == "(?P<year>\\d{4})"
    loc = parse_location(Directive("location", ["~", "(unclosed"], "f", 1, block=[]))
    assert loc.regex is None and loc.regex_error


def test_resolve_outcomes():
    srv = server(r"""
    server {
        location / { try_files $uri $uri/ /index.php?$args; }
        location ~ /\.git { deny all; }
        location = /old { return 301 /new; }
        location /internal/ { internal; }
        location /api/ { proxy_pass http://app; }
        location /private/ { allow 10.0.0.0/8; deny all; }
        location /public/ { allow all; }
        location ~ \.php$ { fastcgi_pass php; }
        location /cond/ { if ($x) { return 403; } }
        location /inc/ { include unknown.conf; }
    }
    """)
    for d in srv.walk():
        if d.name == "include":
            d.include_resolved = False
    assert resolve(srv, "/a.css").outcome is Outcome.STATIC
    assert resolve(srv, "/.git/config").outcome is Outcome.DENIED
    assert resolve(srv, "/old").outcome is Outcome.REDIRECT
    assert resolve(srv, "/internal/x").outcome is Outcome.DENIED
    assert resolve(srv, "/api/x").outcome is Outcome.PROXY
    assert resolve(srv, "/private/x").outcome is Outcome.DENIED
    assert resolve(srv, "/public/x").outcome is Outcome.STATIC
    assert resolve(srv, "/x.php").outcome is Outcome.PHP
    assert resolve(srv, "/cond/x").outcome is Outcome.UNKNOWN
    assert resolve(srv, "/inc/x").outcome is Outcome.UNKNOWN


def test_server_level_return_and_deny():
    assert resolve(server("server { return 301 https://$host$request_uri; }"),
                   "/x").outcome is Outcome.REDIRECT
    assert resolve(server("server { return 444; }"), "/x").outcome is Outcome.DENIED
    assert resolve(server("server { deny all; location / { } }"),
                   "/x").outcome is Outcome.DENIED
    assert resolve(server("server { deny all; location / { allow all; } }"),
                   "/x").outcome is Outcome.STATIC


def test_server_level_if_guard():
    srv = server(r'server { if ($request_uri ~* "/\.git") { return 403; } location / { } }')
    assert resolve(srv, "/.git/config").outcome is Outcome.DENIED
    assert resolve(srv, "/index.html").outcome is Outcome.STATIC


def test_server_rewrite_redirect():
    srv = server("server { rewrite ^/old/(.*)$ /new/$1 permanent; location / { } }")
    assert resolve(srv, "/old/x").outcome is Outcome.REDIRECT
    assert resolve(srv, "/other").outcome is Outcome.STATIC


def test_unresolved_include_in_server_makes_regex_unknown():
    srv = server("server { include extra.conf; location / { } }")
    srv.children[0].include_resolved = False
    assert resolve(srv, "/x.php").outcome is Outcome.UNKNOWN


def test_known_include_does_not_block_resolution():
    srv = server("server { location ~ \\.php$ { include fastcgi_params; fastcgi_pass x; } }")
    srv.children[0].children[0].include_resolved = False
    assert resolve(srv, "/x.php").outcome is Outcome.PHP


@pytest.mark.parametrize(
    ("cond", "uri", "expected"),
    [
        (["($request_uri", "~*", '"\\.git")'], "/.GIT/x", True),
        (["($uri", "!~", "^/wp-)"], "/wp-login.php", False),
        (["($uri", "=", "/x)"], "/x", True),
        (["($uri", "!=", "/x)"], "/x", False),
        (["($http_user_agent", "~", "bot)"], "/x", None),
        (["(-f", "$request_filename)"], "/x", None),
        ([], "/x", None),
    ],
)
def test_evaluate_if(cond, uri, expected):
    assert evaluate_if(Directive("if", cond, "f", 1, block=[]), uri) is expected
