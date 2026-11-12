from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from nginx_wp_lint.config import Settings
from nginx_wp_lint.linter import lint_string

FIXTURES = Path(__file__).parent / "fixtures"


def lint(text: str, *, only: tuple[str, ...] = (), path: str = "site.conf", **settings):
    s = Settings(**settings)
    if only:
        s.enable_only = set(only)
    return lint_string(textwrap.dedent(text), path=path, settings=s)


def rule_ids(text: str, **kwargs) -> list[str]:
    return sorted({f.rule_id for f in lint(text, **kwargs).findings})


def hits(text: str, rule: str, **kwargs):
    return [f for f in lint(text, only=(rule,), **kwargs).findings if f.rule_id == rule]


# A PHP server with nothing that the WordPress rules complain about, used as a
# base that tests modify one aspect of.
WP_SERVER = """
server {
    listen 80;
    server_name wp.example.com;
    root /var/www/wp;
    index index.php;
    %s
    location ~ /\\.(?!well-known/) { deny all; }
    location = /xmlrpc.php { deny all; }
    location = /wp-config.php { deny all; }
    location ~* ^/wp-content/uploads/.*\\.php$ { deny all; }
    location / {
        try_files $uri $uri/ /index.php?$args;
    }
    location ~ \\.php$ {
        try_files $uri =404;
        include fastcgi.conf;
        fastcgi_pass unix:/run/php/php-fpm.sock;
    }
}
"""


def wp(extra: str = "") -> str:
    return WP_SERVER % extra


@pytest.fixture
def fixtures() -> Path:
    return FIXTURES
