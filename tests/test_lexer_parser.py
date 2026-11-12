from __future__ import annotations

import pytest

from nginx_wp_lint.lexer import COMMENT, EOF, STRING, WORD, Lexer, LexError
from nginx_wp_lint.parser import ParseError, parse_string


def kinds(text):
    return [(t.kind, t.value) for t in Lexer(text).tokens()]


def test_basic_tokens():
    assert kinds("listen 80;") == [(WORD, "listen"), (WORD, "80"), (";", ";"), (EOF, "")]


def test_quotes_and_escapes():
    toks = Lexer('add_header X "a \\"b\\" c" \'d;e\';').tokens()
    assert [t.value for t in toks[:4]] == ["add_header", "X", 'a "b" c', "d;e"]
    assert toks[2].kind == STRING


def test_unknown_escape_is_kept_for_regexes():
    toks = Lexer('location ~ "\\.php$" {').tokens()
    assert toks[2].value == "\\.php$"


def test_comment_only_at_token_start():
    toks = Lexer("set $a foo#bar; # real comment\n").tokens()
    assert toks[2].value == "foo#bar"
    comment = next(t for t in toks if t.kind == COMMENT)
    assert comment.value == " real comment"
    assert not comment.first_on_line


def test_standalone_comment_flag():
    toks = Lexer("  # alone\nlisten 80;").tokens()
    assert toks[0].kind == COMMENT and toks[0].first_on_line


def test_variable_braces_stay_in_word():
    toks = Lexer("fastcgi_pass ${backend}:9000;").tokens()
    assert toks[1].value == "${backend}:9000"


def test_line_and_column_tracking():
    toks = Lexer("events {\n    worker_connections 1024;\n}").tokens()
    wc = toks[2]
    assert (wc.value, wc.line, wc.column) == ("worker_connections", 2, 5)


def test_crlf_and_bom():
    toks = Lexer("﻿a 1;\r\nb 2;").tokens()
    assert toks[3].line == 2


def test_unterminated_string():
    with pytest.raises(LexError):
        Lexer('set $a "oops;').tokens()


def test_quote_followed_by_paren_is_allowed():
    toks = Lexer('if ($a ~ "b") {').tokens()
    assert [t.value for t in toks[:5]] == ["if", "($a", "~", "b", ")"]


def test_text_glued_after_quote_is_an_error():
    with pytest.raises(LexError):
        Lexer('set $a "b"c;').tokens()


def test_parse_tree_and_parents():
    pf = parse_string("http {\n  server {\n    listen 80;\n    location / { root /x; }\n  }\n}\n",
                      "n.conf")
    http = pf.directives[0]
    server = http.children[0]
    loc = server.first("location")
    assert http.name == "http" and http.end_line == 6
    assert loc.args == ["/"]
    assert loc.parent is server and server.parent is http
    assert loc.first("root").context == "location"
    assert [d.name for d in http.walk()] == ["server", "listen", "location", "root"]
    assert loc.enclosing("http") is http


@pytest.mark.parametrize(
    ("text", "message", "line"),
    [
        ("server {\n listen 80;\n", 'unexpected end of file, expecting "}"', 3),
        ("listen 80;\n}\n", 'unexpected "}"', 2),
        ("server {\n root /x\n}\n", 'unexpected "}"', 3),
        ("listen 80", 'unexpected end of file, expecting ";" or "}"', 1),
        (";", 'unexpected ";"', 1),
        ("{ }", 'unexpected "{"', 1),
    ],
)
def test_parse_errors(text, message, line):
    with pytest.raises(ParseError) as info:
        parse_string(text, "bad.conf")
    assert info.value.message == message
    assert info.value.line == line
    assert str(info.value).startswith("bad.conf:")


def test_raw_lua_block():
    pf = parse_string('content_by_lua_block {\n  local t = { a = "}" } -- }\n}\nlisten 80;\n')
    lua = pf.directives[0]
    assert lua.raw is not None and 'local t' in lua.raw
    assert lua.children == []
    assert pf.directives[1].name == "listen"


def test_comments_record_block_extent():
    pf = parse_string("server {\n    # first\n    listen 80;\n    # later\n}\n")
    first, later = pf.comments
    assert first.first_in_block and first.block_start == 1 and first.block_end == 5
    assert not later.first_in_block


def test_map_and_types_blocks_parse():
    pf = parse_string("map $http_cookie $x {\n default 0;\n ~*wordpress_logged_in 1;\n}\n"
                      "types { text/html html htm; }\n")
    m = pf.directives[0]
    assert [d.name for d in m.children] == ["default", "~*wordpress_logged_in"]
