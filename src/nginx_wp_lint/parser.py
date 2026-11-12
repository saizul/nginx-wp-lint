"""Parse nginx configuration text into a tree of directives."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field

from .lexer import COMMENT, EOF, LBRACE, RBRACE, SEMI, STRING, Lexer, LexError, Token

ROOT = "__root__"


class ParseError(Exception):
    def __init__(self, message: str, file: str, line: int, column: int = 1) -> None:
        super().__init__(f"{file}:{line}:{column}: {message}")
        self.message = message
        self.file = file
        self.line = line
        self.column = column


@dataclass
class Comment:
    text: str
    file: str
    line: int
    column: int
    standalone: bool  # on a line of its own
    block_start: int | None = None  # line of the enclosing block's opening brace
    block_end: int | None = None  # line of the enclosing block's closing brace
    first_in_block: bool = False  # before the first directive of the block


@dataclass(eq=False)
class Directive:
    """One directive. Block directives (``server``, ``location`` ...) have a
    ``block`` list; simple directives have ``block = None``."""

    name: str
    args: list[str]
    file: str
    line: int
    column: int = 1
    block: list[Directive] | None = None
    parent: Directive | None = field(default=None, repr=False)
    end_line: int | None = None
    quoted: list[bool] = field(default_factory=list, repr=False)
    raw: str | None = field(default=None, repr=False)  # body of *_by_lua_block
    # Set on ``include`` directives by the loader.
    included_files: list[str] = field(default_factory=list, repr=False)
    include_resolved: bool | None = field(default=None, repr=False)
    # The include directive this one was pulled in through, if any.
    via_include: Directive | None = field(default=None, repr=False)

    # -- tree helpers -------------------------------------------------------

    @property
    def is_block(self) -> bool:
        return self.block is not None

    @property
    def children(self) -> list[Directive]:
        return self.block or []

    def find(self, name: str) -> list[Directive]:
        """Direct children with ``name``."""
        return [d for d in self.children if d.name == name]

    def first(self, name: str) -> Directive | None:
        for d in self.children:
            if d.name == name:
                return d
        return None

    def walk(self) -> Iterator[Directive]:
        """All descendants, depth first, in file order."""
        for child in self.children:
            yield child
            yield from child.walk()

    def ancestors(self) -> Iterator[Directive]:
        node = self.parent
        while node is not None:
            yield node
            node = node.parent

    def enclosing(self, name: str) -> Directive | None:
        for node in self.ancestors():
            if node.name == name:
                return node
        return None

    @property
    def context(self) -> str:
        """Name of the enclosing block (``main`` at top level)."""
        if self.parent is None or self.parent.name == ROOT:
            return "main"
        return self.parent.name

    def arg(self, index: int, default: str = "") -> str:
        return self.args[index] if index < len(self.args) else default

    def location_text(self) -> str:
        return f"{self.file}:{self.line}"

    def __str__(self) -> str:
        args = " ".join(self.args)
        return f"{self.name} {args}".strip()


@dataclass
class ParsedFile:
    path: str
    directives: list[Directive]
    comments: list[Comment]
    line_count: int


RAW_BLOCK_SUFFIXES = ("_by_lua_block",)
RAW_BLOCK_NAMES = frozenset({"lua_block", "js_block"})


def _is_raw_block(name: str) -> bool:
    return name in RAW_BLOCK_NAMES or name.endswith(RAW_BLOCK_SUFFIXES)


class _Parser:
    def __init__(self, text: str, path: str) -> None:
        self.lexer = Lexer(text)
        self.path = path
        self.comments: list[Comment] = []

    def _next(self) -> Token:
        try:
            return self.lexer.next_token()
        except LexError as exc:
            raise ParseError(exc.message, self.path, exc.line, exc.column) from exc

    def parse(self) -> list[Directive]:
        items = self._block(parent=None, open_tok=None)
        return items

    def _block(self, parent: Directive | None, open_tok: Token | None) -> list[Directive]:
        items: list[Directive] = []
        block_comments: list[Comment] = []
        words: list[Token] = []
        while True:
            tok = self._next()
            if tok.kind == COMMENT:
                c = Comment(tok.value, self.path, tok.line, tok.column, tok.first_on_line,
                            block_start=open_tok.line if open_tok else None,
                            first_in_block=not items and not words)
                self.comments.append(c)
                block_comments.append(c)
                continue
            if tok.kind == EOF:
                if words:
                    raise ParseError('unexpected end of file, expecting ";" or "}"',
                                     self.path, tok.line, tok.column)
                if open_tok is not None:
                    raise ParseError('unexpected end of file, expecting "}"',
                                     self.path, tok.line, tok.column)
                for c in block_comments:
                    c.block_end = tok.line
                return items
            if tok.kind == RBRACE:
                if words:
                    raise ParseError('unexpected "}"', self.path, tok.line, tok.column)
                if open_tok is None:
                    raise ParseError('unexpected "}"', self.path, tok.line, tok.column)
                if parent is not None:
                    parent.end_line = tok.line
                for c in block_comments:
                    c.block_end = tok.line
                return items
            if tok.kind == SEMI:
                if not words:
                    raise ParseError('unexpected ";"', self.path, tok.line, tok.column)
                items.append(self._directive(words, parent, block=None))
                words = []
                continue
            if tok.kind == LBRACE:
                if not words:
                    raise ParseError('unexpected "{"', self.path, tok.line, tok.column)
                d = self._directive(words, parent, block=[])
                words = []
                if _is_raw_block(d.name):
                    try:
                        d.raw, d.end_line = self.lexer.read_raw_block()
                    except LexError as exc:
                        raise ParseError(exc.message, self.path, exc.line, exc.column) from exc
                else:
                    d.block = self._block(parent=d, open_tok=tok)
                items.append(d)
                continue
            words.append(tok)

    def _directive(self, words: list[Token], parent: Directive | None,
                   block: list[Directive] | None) -> Directive:
        head = words[0]
        return Directive(
            name=head.value,
            args=[w.value for w in words[1:]],
            quoted=[w.kind == STRING for w in words[1:]],
            file=self.path,
            line=head.line,
            column=head.column,
            block=block,
            parent=parent,
        )


def parse_string(text: str, path: str = "<string>") -> ParsedFile:
    parser = _Parser(text, path)
    directives = parser.parse()
    return ParsedFile(path=path, directives=directives, comments=parser.comments,
                      line_count=text.count("\n") + 1)
