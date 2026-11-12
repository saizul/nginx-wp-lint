"""Tokenizer for nginx configuration files.

Follows the rules of nginx's own ``ngx_conf_read_token``: tokens are separated
by whitespace, ``;``, ``{`` and ``}``; single and double quotes group a token
and support backslash escapes; ``#`` starts a comment only at the start of a
token; ``${name}`` inside a word is part of the word.
"""

from __future__ import annotations

from dataclasses import dataclass

WORD = "word"
STRING = "string"  # quoted word
LBRACE = "{"
RBRACE = "}"
SEMI = ";"
COMMENT = "comment"
EOF = "eof"

_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "'": "'", "\\": "\\"}


class LexError(Exception):
    def __init__(self, message: str, line: int, column: int) -> None:
        super().__init__(message)
        self.message = message
        self.line = line
        self.column = column


@dataclass
class Token:
    kind: str
    value: str
    line: int
    column: int
    first_on_line: bool = False  # for comments: nothing but whitespace before it


class Lexer:
    def __init__(self, text: str) -> None:
        # Normalise newlines so line numbers match what editors show.
        self.text = text.replace("\r\n", "\n").replace("\r", "\n")
        if self.text.startswith("﻿"):
            self.text = self.text[1:]
        self.pos = 0
        self.line = 1
        self.col = 1
        self._line_has_token = False

    # -- character helpers -------------------------------------------------

    def _peek(self, offset: int = 0) -> str:
        idx = self.pos + offset
        return self.text[idx] if idx < len(self.text) else ""

    def _advance(self) -> str:
        ch = self.text[self.pos]
        self.pos += 1
        if ch == "\n":
            self.line += 1
            self.col = 1
            self._line_has_token = False
        else:
            self.col += 1
        return ch

    # -- tokens ------------------------------------------------------------

    def tokens(self) -> list[Token]:
        out = []
        while True:
            tok = self.next_token()
            out.append(tok)
            if tok.kind == EOF:
                return out

    def next_token(self) -> Token:
        while self.pos < len(self.text) and self._peek().isspace():
            self._advance()
        if self.pos >= len(self.text):
            return Token(EOF, "", self.line, self.col)
        line, col = self.line, self.col
        first = not self._line_has_token
        self._line_has_token = True
        ch = self._peek()
        if ch == "#":
            start = self.pos
            while self.pos < len(self.text) and self._peek() != "\n":
                self._advance()
            return Token(COMMENT, self.text[start + 1:self.pos], line, col, first)
        if ch in ";{}":
            self._advance()
            return Token(ch, ch, line, col)
        if ch in "\"'":
            return self._quoted(ch, line, col)
        return self._word(line, col)

    def _quoted(self, quote: str, line: int, col: int) -> Token:
        self._advance()
        out = []
        while True:
            if self.pos >= len(self.text):
                raise LexError(f"unterminated {quote} string", line, col)
            ch = self._advance()
            if ch == "\\" and self.pos < len(self.text):
                nxt = self._advance()
                out.append(_ESCAPES.get(nxt, "\\" + nxt))
                continue
            if ch == quote:
                break
            out.append(ch)
        nxt = self._peek()
        # nginx accepts ")" right after a quoted string, as in if ($a ~ "b").
        if nxt and not (nxt.isspace() or nxt in ";{})"):
            raise LexError(f'unexpected "{nxt}" after quoted string', self.line, self.col)
        return Token(STRING, "".join(out), line, col)

    def _word(self, line: int, col: int) -> Token:
        out = []
        while self.pos < len(self.text):
            ch = self._peek()
            if ch.isspace() or ch in ";}":
                break
            if ch == "{":
                if out and out[-1] == "$":
                    # ${variable}
                    while self.pos < len(self.text) and self._peek() != "}":
                        out.append(self._advance())
                    if self.pos < len(self.text):
                        out.append(self._advance())
                    continue
                break
            if ch == "\\" and self.pos + 1 < len(self.text):
                self._advance()
                out.append("\\" + self._advance())
                continue
            out.append(self._advance())
        return Token(WORD, "".join(out), line, col)

    def read_raw_block(self) -> tuple[str, int]:
        """Read the body of a ``*_by_lua_block { ... }`` after its ``{``.

        Returns the raw text and the line of the closing brace. Braces inside
        Lua strings and comments are not counted.
        """
        depth = 1
        start = self.pos
        while self.pos < len(self.text):
            ch = self._advance()
            if ch in "\"'":
                while self.pos < len(self.text):
                    c = self._advance()
                    if c == "\\":
                        if self.pos < len(self.text):
                            self._advance()
                    elif c == ch:
                        break
            elif ch == "-" and self._peek() == "-":
                while self.pos < len(self.text) and self._peek() != "\n":
                    self._advance()
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return self.text[start:self.pos - 1], self.line
        raise LexError("unexpected end of file in raw block, expecting \"}\"", self.line, self.col)
