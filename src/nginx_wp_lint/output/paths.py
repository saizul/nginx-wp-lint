from __future__ import annotations

import os


def display_path(path: str, base: str = ".") -> str:
    """Path relative to ``base`` when it is inside it, with forward slashes."""
    if path.startswith("<"):
        return path
    absolute = os.path.abspath(path)
    root = os.path.abspath(base)
    try:
        rel = os.path.relpath(absolute, root)
    except ValueError:  # different drive on Windows
        rel = absolute
    if rel.startswith(".."):
        rel = absolute
    return rel.replace(os.sep, "/")
