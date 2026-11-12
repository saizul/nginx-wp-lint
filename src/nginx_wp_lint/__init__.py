"""Lint nginx configuration for WordPress and PHP sites."""

from ._version import __version__
from .linter import LintResult, lint_paths, lint_string
from .rules import ALL_RULES, Finding, Severity

__all__ = ["ALL_RULES", "Finding", "LintResult", "Severity", "__version__", "lint_paths",
           "lint_string"]
