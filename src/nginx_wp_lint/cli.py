"""Command-line interface."""

from __future__ import annotations

import argparse
import os
import sys
import textwrap
from collections.abc import Sequence
from typing import TextIO

from . import baseline as baseline_mod
from ._version import __version__
from .config import ConfigError, Settings, apply_dict, discover, load_file
from .linter import lint_paths
from .loader import load
from .output import FORMATS, render
from .parser import Directive
from .rules import ALL_RULES, Severity, UnknownRuleError, lookup

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_PARSE = 3

SEVERITIES = [s.value for s in Severity]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="nginx-wp-lint",
        description="Lint nginx configuration for WordPress and PHP sites.",
        epilog="Exit status: 0 no problems at or above --fail-on, 1 problems found, "
               "2 usage or config error, 3 a file could not be read or parsed.",
    )
    p.add_argument("paths", nargs="*", metavar="PATH",
                   help="nginx.conf, a site file, or a directory (default: /etc/nginx if it "
                        "exists, else the current directory)")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("-f", "--format", choices=FORMATS, default="text")
    p.add_argument("-o", "--output", metavar="FILE", help="write the report to FILE")
    p.add_argument("-c", "--config", metavar="FILE",
                   help="config file (default: .nginx-wp-lint.toml/.yml or "
                        "[tool.nginx-wp-lint] in pyproject.toml in the current directory)")
    p.add_argument("--no-config", action="store_true", help="ignore config files")
    p.add_argument("--fail-on", choices=[*SEVERITIES, "never"],
                   help="exit 1 if a problem at or above this severity is found (default low)")
    p.add_argument("--min-severity", choices=SEVERITIES,
                   help="do not report problems below this severity (default info)")
    p.add_argument("--disable", action="append", default=[], metavar="RULES",
                   help="comma separated rule ids or names to turn off")
    p.add_argument("--enable-only", metavar="RULES", help="run only these rules")
    p.add_argument("--severity", action="append", default=[], metavar="RULE=LEVEL",
                   help="override the severity of a rule, e.g. NWL014=low")
    p.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                   help="skip files matching GLOB")
    p.add_argument("--prefix", metavar="DIR",
                   help="directory relative includes are resolved against (like nginx -p)")
    p.add_argument("--no-includes", action="store_true", help="do not follow include")
    p.add_argument("--base", metavar="DIR", default=".",
                   help="report paths relative to DIR (default: current directory)")
    p.add_argument("--baseline", metavar="FILE",
                   help="ignore problems recorded in this baseline file and report only new "
                        "ones (see --write-baseline)")
    p.add_argument("--write-baseline", metavar="FILE",
                   help="record every current problem in FILE and exit 0, so later runs "
                        "with --baseline only fail on new problems")
    p.add_argument("--no-baseline", action="store_true",
                   help="ignore a baseline set in the config file")
    p.add_argument("-q", "--quiet", action="store_true", help="text format: no hints or summary")
    p.add_argument("--list-rules", action="store_true", help="list rules and exit")
    p.add_argument("--explain", metavar="RULE", help="describe one rule and exit")
    p.add_argument("--print-tree", action="store_true",
                   help="print the parsed directive tree (with includes) and exit")
    return p


def _settings(args: argparse.Namespace) -> Settings:
    settings = Settings()
    if args.config:
        settings = load_file(args.config, settings)
    elif not args.no_config:
        found = discover(".")
        if found is not None:
            settings = load_file(found, settings)
    cli: dict = {}
    if args.fail_on:
        cli["fail_on"] = args.fail_on
    if args.min_severity:
        cli["min_severity"] = args.min_severity
    disabled = [part for value in args.disable for part in value.split(",") if part.strip()]
    if disabled:
        cli["disable"] = disabled
    if args.enable_only:
        cli["enable_only"] = [p for p in args.enable_only.split(",") if p.strip()]
    if args.exclude:
        cli["exclude"] = args.exclude
    if args.severity:
        sev = {}
        for item in args.severity:
            if "=" not in item:
                raise ConfigError(f"--severity expects RULE=LEVEL, got {item!r}")
            rule, level = item.split("=", 1)
            sev[rule.strip()] = level.strip()
        cli["severity"] = sev
    if args.prefix:
        cli["prefix"] = args.prefix
    if args.no_includes:
        cli["follow_includes"] = False
    if args.baseline:
        cli["baseline"] = args.baseline
    if args.no_baseline:
        cli["baseline"] = None
    return apply_dict(settings, cli, source="command line")


def list_rules(out: TextIO) -> None:
    width = max(len(r.name) for r in ALL_RULES)
    for r in ALL_RULES:
        out.write(f"{r.id}  {r.severity.value:<6}  {r.name:<{width}}  {r.summary}\n")


def explain(ref: str, out: TextIO) -> None:
    r = lookup(ref)
    out.write(f"{r.id} {r.name}\n")
    out.write(f"  severity: {r.severity.value}\n  category: {r.category}\n")
    if r.http_level:
        out.write("  scope:    http-level setting (info only when linting a file without an "
                  "http block)\n")
    out.write("\n" + textwrap.fill(r.summary, 80, initial_indent="  ",
                                   subsequent_indent="  ") + "\n\n")
    out.write(textwrap.fill("Fix: " + r.hint, 80, initial_indent="  ",
                            subsequent_indent="       ") + "\n")


def print_tree(paths: list[str], settings: Settings, out: TextIO) -> None:
    def emit(d: Directive, depth: int) -> None:
        loc = f"{d.file}:{d.line}"
        args = " ".join(d.args)
        extra = ""
        if d.name == "include":
            extra = (f"  -> {', '.join(d.included_files) or 'no files'}"
                     if d.include_resolved else "  -> NOT FOUND")
        out.write(f"{'  ' * depth}{d.name} {args}{' {' if d.is_block else ';'}"
                  f"{extra}    # {loc}\n")
        for child in d.children:
            emit(child, depth + 1)
        if d.is_block:
            out.write(f"{'  ' * depth}}}\n")

    for path in paths:
        cfg = load(path, prefix=settings.prefix, follow_includes=settings.follow_includes)
        out.write(f"# {cfg.path}\n")
        for err in cfg.errors:
            out.write(f"# error: {err}\n")
        for d in cfg.root.children:
            emit(d, 0)


def write_baseline(result, path: str, base: str, err: TextIO) -> int:
    """Store every current finding in a baseline file."""
    data = baseline_mod.Baseline.from_findings(result.findings, base=base)
    try:
        data.write(path)
    except baseline_mod.BaselineError as exc:
        print(f"nginx-wp-lint: error: {exc}", file=err)
        return EXIT_USAGE
    print(f"wrote baseline {path} ({len(data.entries)} problem(s))", file=err)
    if result.parse_errors:
        print("nginx-wp-lint: warning: parse errors are recorded in the baseline too; "
              "fix them before relying on it", file=err)
        return EXIT_PARSE
    return EXIT_OK


def default_paths() -> list[str]:
    return ["/etc/nginx"] if os.path.isdir("/etc/nginx") else ["."]


def main(argv: Sequence[str] | None = None, stdout: TextIO | None = None,
         stderr: TextIO | None = None) -> int:
    out = stdout or sys.stdout
    err = stderr or sys.stderr
    args = build_parser().parse_args(argv)
    try:
        if args.list_rules:
            list_rules(out)
            return EXIT_OK
        if args.explain:
            explain(args.explain, out)
            return EXIT_OK
        settings = _settings(args)
    except (ConfigError, UnknownRuleError) as exc:
        print(f"nginx-wp-lint: error: {exc}", file=err)
        return EXIT_USAGE
    paths = args.paths or default_paths()
    missing = [p for p in paths if not os.path.exists(p)]
    if missing:
        print(f"nginx-wp-lint: error: no such file or directory: {', '.join(missing)}",
              file=err)
        return EXIT_USAGE
    if args.print_tree:
        from .linter import expand_paths

        print_tree(expand_paths(paths, settings.exclude), settings, out)
        return EXIT_OK
    result = lint_paths(paths, settings)
    for warning in result.warnings:
        print(f"nginx-wp-lint: warning: {warning}", file=err)
    if not result.roots:
        print("nginx-wp-lint: error: no configuration files found", file=err)
        return EXIT_USAGE
    if args.write_baseline:
        return write_baseline(result, args.write_baseline, args.base, err)
    if settings.baseline:
        try:
            accepted = baseline_mod.load(settings.baseline)
        except baseline_mod.BaselineError as exc:
            print(f"nginx-wp-lint: error: {exc}", file=err)
            return EXIT_USAGE
        match = baseline_mod.apply(result.findings, accepted, base=args.base)
        result.findings = match.new
        result.baselined = match.matched
        result.baseline_stale = len(match.stale)
        if match.stale and not args.quiet:
            print(f"nginx-wp-lint: note: {len(match.stale)} baseline entr"
                  f"{'y' if len(match.stale) == 1 else 'ies'} no longer match; run "
                  f"--write-baseline {settings.baseline} to prune", file=err)
    text = render(result, args.format, base=args.base, quiet=args.quiet)
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(text)
        except OSError as exc:
            print(f"nginx-wp-lint: error: cannot write {args.output}: {exc.strerror or exc}",
                  file=err)
            return EXIT_USAGE
        if args.format != "text" or not args.quiet:
            print(f"wrote {args.output} ({len(result.findings)} problem(s))", file=err)
    else:
        out.write(text)
    if result.parse_errors:
        return EXIT_PARSE
    if settings.fail_on is not None and any(
            f.severity.rank >= settings.fail_on.rank for f in result.findings):
        return EXIT_FINDINGS
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
