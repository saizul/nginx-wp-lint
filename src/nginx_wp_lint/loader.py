"""Load a configuration file and splice in its ``include`` files."""

from __future__ import annotations

import glob
import os
from dataclasses import dataclass, field
from pathlib import Path

from .parser import ROOT, Directive, ParsedFile, ParseError, parse_string

GLOB_CHARS = set("*?[")
MAX_INCLUDE_DEPTH = 32


@dataclass
class LoadedConfig:
    """A root file with every include resolved, as one directive tree."""

    path: str
    root: Directive
    files: dict[str, ParsedFile] = field(default_factory=dict)
    errors: list[ParseError] = field(default_factory=list)
    missing_includes: list[Directive] = field(default_factory=list)
    prefix: str | None = None

    @property
    def ok(self) -> bool:
        return not self.errors


def display_path(path: str) -> str:
    """Relative to the working directory when inside it, else absolute."""
    absolute = os.path.abspath(path)
    try:
        rel = os.path.relpath(absolute)
    except ValueError:  # pragma: no cover - other drive on Windows
        return absolute
    return absolute if rel.startswith("..") else rel


def _read(path: str) -> str:
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def default_prefixes(path: str, explicit: str | None) -> list[str]:
    """Directories that relative include paths are tried against.

    nginx resolves them against its configuration prefix (the directory of
    ``nginx.conf``, e.g. ``/etc/nginx``). For a site file such as
    ``/etc/nginx/sites-enabled/example.conf`` that is the parent directory.
    """
    here = os.path.dirname(os.path.abspath(path))
    out = []
    if explicit:
        out.append(os.path.abspath(explicit))
    out.append(here)
    parent = os.path.dirname(here)
    if parent and parent != here:
        out.append(parent)
    seen = []
    for p in out:
        if p not in seen:
            seen.append(p)
    return seen


class Loader:
    def __init__(self, prefix: str | None = None, follow_includes: bool = True) -> None:
        self.prefix = prefix
        self.follow_includes = follow_includes

    def load(self, path: str) -> LoadedConfig:
        display = display_path(path)
        root = Directive(name=ROOT, args=[], file=display, line=0, block=[])
        config = LoadedConfig(path=display, root=root)
        self._prefixes = default_prefixes(path, self.prefix)
        config.prefix = self._prefixes[0]
        try:
            text = _read(path)
        except OSError as exc:
            config.errors.append(ParseError(f"cannot read file: {exc.strerror or exc}",
                                            display, 1))
            return config
        try:
            parsed = parse_string(text, display)
        except ParseError as exc:
            config.errors.append(exc)
            return config
        config.files[display] = parsed
        root.block = parsed.directives
        for d in root.block:
            d.parent = root
        self._process(root, config, [os.path.abspath(path)])
        return config

    def _resolve(self, pattern: str) -> tuple[list[str], bool]:
        """Return (files, resolved). A glob with no match is resolved and empty."""
        is_glob = any(c in GLOB_CHARS for c in pattern)
        candidates = [pattern] if os.path.isabs(pattern) else [
            os.path.join(p, pattern) for p in self._prefixes]
        for cand in candidates:
            if is_glob:
                matches = sorted(m for m in glob.glob(cand) if os.path.isfile(m))
                if matches:
                    return matches, True
            elif os.path.isfile(cand):
                return [cand], True
        return [], is_glob

    def _process(self, owner: Directive, config: LoadedConfig, stack: list[str]) -> None:
        self._process_list(owner.block or [], owner, config, stack)

    def _include(self, inc: Directive, owner: Directive, config: LoadedConfig,
                 stack: list[str]) -> list[Directive]:
        pattern = inc.args[0]
        files, resolved = self._resolve(pattern)
        inc.include_resolved = resolved
        inc.included_files = [display_path(f) for f in files]
        if not resolved:
            config.missing_includes.append(inc)
            return []
        out: list[Directive] = []
        for path in files:
            abspath = os.path.abspath(path)
            display = display_path(path)
            if abspath in stack:
                config.errors.append(ParseError(f"include cycle: {display} includes itself",
                                                inc.file, inc.line, inc.column))
                continue
            if len(stack) >= MAX_INCLUDE_DEPTH:
                config.errors.append(ParseError("includes nested too deeply", inc.file,
                                                inc.line, inc.column))
                continue
            try:
                parsed = parse_string(_read(path), display)
            except ParseError as exc:
                config.errors.append(exc)
                inc.include_resolved = False
                continue
            except OSError as exc:
                config.errors.append(ParseError(f"cannot read include: {exc.strerror or exc}",
                                                inc.file, inc.line, inc.column))
                inc.include_resolved = False
                continue
            config.files.setdefault(display, parsed)
            for d in parsed.directives:
                d.parent = owner
                d.via_include = inc
            # Includes inside the included file resolve with the same owner.
            self._process_list(parsed.directives, owner, config, [*stack, abspath])
            out.extend(parsed.directives)
        return out

    def _process_list(self, items: list[Directive], owner: Directive, config: LoadedConfig,
                      stack: list[str]) -> None:
        i = 0
        while i < len(items):
            d = items[i]
            if d.name == "include" and d.args and self.follow_includes:
                spliced = self._include(d, owner, config, stack)
                items[i + 1:i + 1] = spliced
                i += 1 + len(spliced)
                continue
            if d.block is not None:
                self._process(d, config, stack)
            i += 1


def load(path: str | Path, prefix: str | None = None,
         follow_includes: bool = True) -> LoadedConfig:
    return Loader(prefix=prefix, follow_includes=follow_includes).load(str(path))
