# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Rule IDs are stable: a rule may change severity or wording in a minor release,
but its ID and name keep their meaning.

## [Unreleased]

### Added

- `NWL023` `static-assets-no-cache` (low, performance): a WordPress site serves
  theme CSS, core JavaScript or uploaded images without `expires` or a
  `Cache-Control` header, so browsers revalidate them on every page view. The
  rule asks which location serves typical asset URLs and reports which kinds are
  affected; `expires off`/`epoch` count as no lifetime, and locations whose
  includes cannot be read are skipped.
- Baseline files: `--write-baseline FILE` records every current problem, and
  `--baseline FILE` (or `baseline = "..."` in the config file) reports and
  fails only on problems that are not in it. Fingerprints ignore line numbers,
  so unrelated edits keep the baseline valid, and identical problems are
  counted. Entries that no longer match are reported as stale on stderr and as
  `summary.baseline_stale` in JSON output; `--no-baseline` ignores a configured
  baseline.
- JSON output: `summary.baselined` and `summary.baseline_stale`; the text
  summary mentions baselined problems.
- `CODE_OF_CONDUCT.md`, issue forms for bug reports and feature requests, and
  a pull request template.

## [0.1.0] - 2026-11-12

First public release.

### Added

- nginx configuration tokenizer and parser with line and column numbers,
  quoted strings, escapes, `${var}`, comments and raw `*_by_lua_block` bodies.
- `include` resolution with globs, nginx-style prefix lookup, cycle detection,
  and known contents for standard files (`fastcgi_params`, `fastcgi.conf`,
  `snippets/fastcgi-php.conf`, `mime.types` ...).
- Location matching that follows nginx (exact, longest prefix, `^~`, regex
  order, nested locations) and request outcome resolution (deny, return,
  rewrite, server-level `if` URI guards, allow/deny inheritance, internal).
- 44 rules: server tokens, autoindex, exposed dotfiles, backups and logs,
  wp-config.php, xmlrpc.php, PHP in uploads, PHP source disclosure, blocked
  ACME challenges, HSTS, X-Content-Type-Options, Referrer-Policy, CSP,
  clickjacking protection, add_header inheritance, `always`, gzip/brotli,
  gzip_types, client_max_body_size, FastCGI cache zone/key/bypass/valid, weak
  TLS protocols and ciphers, removed `ssl on`, deprecated `listen ... http2`,
  missing HTTPS redirect, `listen 443` without ssl, default ssl_protocols,
  permalinks, PHP file check, SCRIPT_FILENAME, wp-login.php rate limiting,
  undefined limit_req zones, `if` pitfalls, alias traversal, duplicate
  server names, root in locations and missing includes.
- Text, JSON, SARIF 2.1.0 and GitHub Actions annotation output.
- TOML/YAML/pyproject configuration, severity overrides, rule options,
  excludes, and inline `disable`, `disable-next-line`, `disable-file` and
  `enable` comments.
- `--list-rules`, `--explain` and `--print-tree`.
- Container image published to `ghcr.io/saizul/nginx-wp-lint`.

[Unreleased]: https://github.com/saizul/nginx-wp-lint/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/saizul/nginx-wp-lint/releases/tag/v0.1.0
