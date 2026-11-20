# nginx-wp-lint

[![CI](https://github.com/saizul/nginx-wp-lint/actions/workflows/ci.yml/badge.svg)](https://github.com/saizul/nginx-wp-lint/actions/workflows/ci.yml)
![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

A linter for nginx configurations that serve WordPress and other PHP sites.
It finds the mistakes that matter on a real server: `.git` and backup files
that can be downloaded, PHP that runs from `wp-content/uploads`, security
headers that silently disappear in one location, a FastCGI cache that serves
logged-in pages to visitors, weak TLS, and the classic "if is evil" and alias
traversal traps.

`nginx -t` tells you whether a configuration loads. `nginx-wp-lint` tells you
what it actually does with a request.

```console
$ nginx-wp-lint examples/naive-site.conf
...
naive-site.conf:2:1: high NWL007 php-in-uploads: an uploaded .php file would run:
/wp-content/uploads/2026/01/shell.php is handled by location ~ \.php$ (line 18) [blog.example.com:80]
    hint: Deny PHP in uploads with a regex location placed BEFORE the PHP location: ...
...
naive-site.conf:7:5: medium NWL002 autoindex-on: autoindex on lists directory contents,
including backups and uploads
...

17 problems (3 high, 5 medium, 5 low, 4 info) in 1 file
```

(Lines wrapped here for readability; the full output is in
[`examples/sample-output.txt`](examples/sample-output.txt).)

## Features

- **A real parser**: tokenizer and block tree that follow nginx's own rules
  (quotes, escapes, `${var}`, comments, `*_by_lua_block` bodies), exact
  line and column numbers, `include` with globs resolved like nginx does
  (relative to the configuration prefix), include cycles detected, clear
  syntax errors.
- **Request simulation**: rules do not grep for patterns. They ask the
  configuration what happens to concrete URIs (`/.git/config`,
  `/wp-content/uploads/x.php`, `/xmlrpc.php`, `/wp-config.php.bak` ...)
  using nginx's location selection algorithm: exact matches, longest prefix,
  `^~`, regex order, nested locations, server-level `return`/`rewrite`/`if`
  guards and `allow`/`deny` inheritance. A prefix `location /wp-content/uploads/`
  that does not stop the regex PHP location is caught; a `^~` one is not
  reported.
- **Inheritance aware**: `add_header` replacement (and `add_header_inherit
  merge`), `fastcgi_param`, `limit_req`, `try_files` and http/server/location
  defaults are resolved the way nginx resolves them.
- **45 rules** with stable IDs, names, severities and fix hints, covering
  security, headers, TLS, WordPress/PHP-FPM, caching, performance and
  correctness. `--explain RULE` prints the details.
- **Honest about what it cannot see**: when an `include` cannot be read, rules
  that depend on it stay silent instead of guessing (standard files such as
  `fastcgi_params` and `snippets/fastcgi-php.conf` are understood by name).
  Linting a single site file without `nginx.conf` downgrades http-level
  findings to `info`.
- **Configurable** in TOML or YAML: disable rules, change severities, set
  thresholds, exclude files. Inline comments disable rules per line, block or
  file.
- **Outputs**: text, JSON, SARIF 2.1.0 (GitHub code scanning, with
  security-severity) and GitHub Actions annotations. Meaningful exit codes.
- **No runtime dependencies** beyond the standard library (`tomli` on
  Python < 3.11; PyYAML only for YAML config).

## Installation

The project is not on PyPI yet. Install it from a checkout:

```console
$ git clone https://github.com/saizul/nginx-wp-lint.git
$ cd nginx-wp-lint
$ python -m pip install .            # or: pip install ".[yaml]" for YAML config
```

This installs the `nginx-wp-lint` command; `python -m nginx_wp_lint` works too.

## Usage

```console
# The whole server configuration (default when /etc/nginx exists)
$ nginx-wp-lint /etc/nginx

# One site file; includes are resolved against its parent directory
$ nginx-wp-lint /etc/nginx/sites-available/example.com

# A copy of the configuration kept in a repository
$ nginx-wp-lint deploy/nginx --prefix deploy/nginx

# Only some rules, or without some rules
$ nginx-wp-lint /etc/nginx --enable-only php-in-uploads,dotfiles-exposed
$ nginx-wp-lint /etc/nginx --disable NWL014 --disable header-without-always

# Machine-readable output
$ nginx-wp-lint /etc/nginx -f json
$ nginx-wp-lint /etc/nginx -f sarif -o nginx.sarif
$ nginx-wp-lint /etc/nginx -f github

# What does a rule check, and how do I fix it?
$ nginx-wp-lint --list-rules
$ nginx-wp-lint --explain NWL015

# See exactly what was parsed, includes spliced in
$ nginx-wp-lint --print-tree /etc/nginx

# Accept today's problems, fail only on new ones
$ nginx-wp-lint deploy/nginx --write-baseline .nginx-wp-lint-baseline.json
$ nginx-wp-lint deploy/nginx --baseline .nginx-wp-lint-baseline.json
```

A directory that contains `nginx.conf` is linted through that file (and its
includes). Any other directory is scanned for `*.conf` files and the files in
`sites-enabled/` and `sites-available/` (Debian and Ubuntu site files have no
extension). A file that another linted file includes is not linted twice.

### Options

| Option | Meaning |
|---|---|
| `-f, --format` | `text` (default), `json`, `sarif`, `github` |
| `-o, --output FILE` | Write the report to a file |
| `-c, --config FILE` / `--no-config` | Use this config file / ignore config files |
| `--fail-on LEVEL` | Exit 1 if a problem at or above `info`, `low` (default), `medium` or `high` is found; `never` to always exit 0 |
| `--min-severity LEVEL` | Hide problems below this level |
| `--disable RULES`, `--enable-only RULES` | Rule ids or names, comma separated; `--disable` may be repeated |
| `--severity RULE=LEVEL` | Override a rule's severity (repeatable) |
| `--exclude GLOB` | Skip matching files (repeatable) |
| `--prefix DIR` | Resolve relative includes against DIR, like `nginx -p` |
| `--no-includes` | Do not follow `include` |
| `--base DIR` | Report paths relative to DIR (also used for baseline fingerprints) |
| `--baseline FILE` | Do not report problems recorded in this baseline file |
| `--write-baseline FILE` | Record all current problems in FILE and exit 0 (3 if a file did not parse) |
| `--no-baseline` | Ignore a `baseline` set in the config file |
| `-q, --quiet` | Text output without hints and summary |

### Exit codes

| Code | Meaning |
|---|---|
| 0 | No problem at or above `--fail-on` |
| 1 | At least one problem at or above `--fail-on` |
| 2 | Usage or configuration error (bad option, unknown rule, missing path) |
| 3 | A file could not be read or parsed (reported as `NWL000`) |

## Rule reference

Severities: `high` (exploitable or breaks the site), `medium`, `low`,
`info`. Rules marked *(http-level)* check settings that usually live in the
http block of `nginx.conf`: when the input has no http block and the setting
is simply absent, they report at `info` with a note.

| ID | Name | Severity | Category | What it reports |
|---|---|---|---|---|
| `NWL000` | `parse-error` | high | syntax | The file could not be read or parsed |
| `NWL001` | `server-tokens` | low | security | server_tokens is not off, so every response and error page shows the nginx version *(http-level)* |
| `NWL002` | `autoindex-on` | medium | security | Directory listings are enabled |
| `NWL003` | `dotfiles-exposed` | high | security | Hidden files such as .git/, .env and .htaccess can be downloaded |
| `NWL004` | `sensitive-files-exposed` | high | security | Backups, database dumps, wp-config.php copies and log files are served if they exist |
| `NWL005` | `wp-config-not-denied` | low | security | Requests for wp-config.php reach PHP |
| `NWL006` | `xmlrpc-not-blocked` | medium | wordpress | xmlrpc.php is reachable (brute force amplification and pingback abuse) |
| `NWL007` | `php-in-uploads` | high | wordpress | PHP files inside wp-content/uploads are executed |
| `NWL008` | `php-source-disclosure` | high | wordpress | PHP files are served as plain text instead of being executed |
| `NWL009` | `acme-challenge-blocked` | low | security | A dotfile rule also blocks /.well-known/acme-challenge/ (certificate renewal) |
| `NWL010` | `hsts-missing` | medium | headers | HTTPS server without Strict-Transport-Security |
| `NWL011` | `hsts-weak` | low | headers | Strict-Transport-Security max-age is shorter than recommended |
| `NWL012` | `x-content-type-options-missing` | low | headers | X-Content-Type-Options: nosniff is not set |
| `NWL013` | `referrer-policy-missing` | low | headers | Referrer-Policy is not set |
| `NWL014` | `csp-missing` | info | headers | No Content-Security-Policy (or Report-Only) header |
| `NWL015` | `add-header-inheritance` | medium | headers | A location with its own add_header loses the security headers set at the server or http level |
| `NWL016` | `clickjacking-protection-missing` | low | headers | Neither X-Frame-Options nor a CSP frame-ancestors directive is set |
| `NWL017` | `header-without-always` | info | headers | Security headers without `always` are missing from error responses |
| `NWL020` | `gzip-disabled` | low | performance | Neither gzip nor brotli compression is enabled *(http-level)* |
| `NWL021` | `gzip-types-default` | low | performance | gzip is on but gzip_types is not set, so only text/html is compressed |
| `NWL022` | `client-max-body-size` | low | wordpress | client_max_body_size is missing (1 MB default), too small, or unlimited *(http-level)* |
| `NWL023` | `static-assets-no-cache` | low | performance | CSS, JavaScript and images are served without a cache lifetime (`expires` or `Cache-Control`), so browsers revalidate them on every page view |
| `NWL030` | `fastcgi-cache-zone-undefined` | high | cache | fastcgi_cache names a zone that no fastcgi_cache_path defines |
| `NWL031` | `fastcgi-cache-key-missing` | high | cache | fastcgi_cache is used without fastcgi_cache_key *(http-level)* |
| `NWL032` | `fastcgi-cache-no-bypass` | high | cache | FastCGI cache without a bypass for logged-in users, carts and POST requests: private pages can be cached and shown to visitors |
| `NWL033` | `fastcgi-cache-valid-missing` | info | cache | fastcgi_cache without fastcgi_cache_valid caches only responses with cache headers |
| `NWL040` | `weak-ssl-protocols` | high | tls | ssl_protocols enables SSLv2, SSLv3, TLSv1 or TLSv1.1 |
| `NWL041` | `weak-ssl-ciphers` | medium | tls | ssl_ciphers allows broken or weak ciphers (RC4, DES/3DES, MD5, NULL, EXPORT ...) |
| `NWL042` | `ssl-directive-removed` | medium | tls | `ssl on;` was removed in nginx 1.25.1 |
| `NWL043` | `listen-http2-deprecated` | info | tls | The http2 parameter of listen is deprecated since nginx 1.25.1 |
| `NWL044` | `https-redirect-missing` | medium | tls | A site is available over HTTPS but plain HTTP is served instead of redirected |
| `NWL045` | `listen-443-without-ssl` | high | tls | listen 443 without the ssl parameter speaks plain HTTP on the HTTPS port |
| `NWL046` | `ssl-protocols-unset` | info | tls | HTTPS server relies on the default ssl_protocols *(http-level)* |
| `NWL050` | `permalinks-try-files` | medium | wordpress | Pretty permalinks are not routed to index.php |
| `NWL051` | `php-location-no-file-check` | medium | wordpress | The PHP location passes requests for non-existent scripts to PHP-FPM (path info tricks such as /uploads/image.jpg/x.php) |
| `NWL052` | `script-filename-missing` | medium | wordpress | fastcgi_pass without SCRIPT_FILENAME: PHP-FPM answers with blank pages |
| `NWL060` | `wp-login-no-rate-limit` | medium | wordpress | wp-login.php has no limit_req rate limiting (password brute force) |
| `NWL061` | `limit-req-zone-undefined` | high | wordpress | limit_req uses a zone that no limit_req_zone defines |
| `NWL070` | `if-in-location` | medium | correctness | `if` inside a location does more than return or rewrite ("if is evil") |
| `NWL071` | `if-host-redirect` | info | correctness | Redirecting by testing $host in an `if` |
| `NWL072` | `if-file-check` | low | correctness | File existence check with `if` and rewrite instead of try_files |
| `NWL073` | `alias-traversal` | high | security | Prefix location without a trailing slash uses an alias with one (path traversal) |
| `NWL074` | `duplicate-server-name` | medium | correctness | The same server_name is used by two servers on the same port |
| `NWL075` | `root-in-location` | info | correctness | root is set inside locations but not in the server block |
| `NWL090` | `include-not-found` | info | syntax | An include matched no file, so rules that depend on it were skipped |

Every rule has a fix hint, shown in text output and with
`nginx-wp-lint --explain <id or name>`.

### How the exposure rules decide

Rules NWL003 to NWL009, NWL050 and NWL060 resolve test URIs against every
server block that handles PHP (it has `fastcgi_pass`, `index index.php` or a
`try_files` falling back to `index.php`):

| Rule | Test URIs | Reported when the request is |
|---|---|---|
| NWL003 | `/.git/config`, `/.env`, `/.htaccess`, `/.user.ini`, `/.svn/entries` | served from disk or by PHP |
| NWL004 | `/wp-config.php.bak`, `/wp-config.php~`, `/backup.sql`, `/wp-content/debug.log`, WooCommerce logs, All-in-One WP Migration, UpdraftPlus and Duplicator backups, plus `extra_sensitive_paths` | served from disk |
| NWL005 | `/wp-config.php` | passed to PHP |
| NWL006 | `/xmlrpc.php` | passed to PHP |
| NWL007 | `/wp-content/uploads/2026/01/shell.php` | passed to PHP |
| NWL008 | `/wp-config.php`, `/index.php`, `/wp-login.php` | served from disk (source code) |
| NWL009 | `/.well-known/acme-challenge/token123` | denied |

A request counts as denied by `deny all` (with allow/deny inheritance),
`return 4xx/444`, `internal`, or a server-level `if ($uri ~ ...)` /
`if ($request_uri ~ ...)` guard that returns an error. A redirect never counts
as exposure. If the deciding location depends on a file that could not be read,
or on an `if` with a condition other than the URI, the request is "unknown" and
nothing is reported.

## Configuration

`nginx-wp-lint` reads, in order, the file given with `--config`, or the first
of `.nginx-wp-lint.toml`, `nginx-wp-lint.toml`, `.nginx-wp-lint.yml`,
`.nginx-wp-lint.yaml` in the current directory, or a `[tool.nginx-wp-lint]`
table in `pyproject.toml`. Command-line options win over the file.

```toml
fail_on = "medium"            # info | low | medium | high | never
min_severity = "low"
disable = ["csp-missing", "NWL075"]
exclude = ["**/legacy/*.conf"]
# prefix = "/etc/nginx"
# follow_includes = true
# baseline = ".nginx-wp-lint-baseline.json"   # relative to this file

[severity]
NWL013 = "info"
"xmlrpc-not-blocked" = "high"

[options]
client_max_body_size_min = "64m"          # NWL022 (default 8m)
hsts_min_max_age = 31536000               # NWL011 (default 15552000)
logged_in_cookie = "wordpress_logged_in"  # NWL032
extra_sensitive_paths = ["/wp-content/uploads/exports/orders.csv"]  # NWL004
```

YAML works the same way (`pip install "nginx-wp-lint[yaml]"`). See
[`examples/.nginx-wp-lint.toml`](examples/.nginx-wp-lint.toml) and
[`examples/nginx-wp-lint.yml`](examples/nginx-wp-lint.yml). Unknown keys,
rules and options are errors, so typos do not pass silently.

### Inline suppressions

```nginx
# nginx-wp-lint: disable-file=NWL014              (whole file)

server {
    # nginx-wp-lint: disable=xmlrpc-not-blocked   (first line in a block: the
    #                                               whole block, including "server {")
    listen 80;
    autoindex on;  # nginx-wp-lint: disable=NWL002   (this line)

    # nginx-wp-lint: disable-next-line=NWL075
    location / { root /var/www; }

    # nginx-wp-lint: disable=NWL070
    ...                                           (until the end of the block)
    # nginx-wp-lint: enable=NWL070                (or until this)
}
```

Rules are named by id or name, comma separated, or `all`. Unknown names
produce a warning. Suppressed findings are counted in the summary.

### Baselines

A large existing configuration can have dozens of findings that cannot all be
fixed before the linter is switched on in CI. A baseline records them once, so
that later runs only report, and fail on, problems that are new:

```console
$ nginx-wp-lint deploy/nginx --write-baseline .nginx-wp-lint-baseline.json
wrote baseline .nginx-wp-lint-baseline.json (23 problem(s))
$ git add .nginx-wp-lint-baseline.json
$ nginx-wp-lint deploy/nginx --baseline .nginx-wp-lint-baseline.json
no problems in 9 files, 23 baselined
```

Or set `baseline = ".nginx-wp-lint-baseline.json"` in the config file (the
path is relative to the config file; `--no-baseline` turns it off for one run).

- **What is matched.** Each entry is a fingerprint of the rule id, the file
  path relative to `--base`, the server context, the message and the
  whitespace-normalised text of the reported line. Line numbers are not part of
  it, so adding or removing lines elsewhere keeps the baseline valid; editing
  the reported directive (or the `server {` line for server-level findings)
  makes the problem show up again. Run with the same `--base` as when the
  baseline was written.
- **Duplicates are counted.** If the baseline holds two identical entries, a
  third copy of the same problem is reported.
- **Fixed problems.** Entries that no longer match anything are counted as
  `baseline_stale` in JSON output and mentioned on stderr (unless `-q`). Run
  `--write-baseline` again to prune them; review the diff of the baseline file
  like any other change.
- Inline suppressions, `--disable` and `--min-severity` are applied first, so
  baselined findings are only those that would otherwise be reported. JSON
  output reports the count as `summary.baselined`.

## Examples

- [`examples/wordpress-hardened/`](examples/wordpress-hardened/): a complete
  `nginx.conf` with snippets for a WordPress site behind HTTPS with FastCGI
  cache, rate-limited login, security headers and hardening rules. It lints
  clean and is a reasonable starting point for your own server.
- [`examples/naive-site.conf`](examples/naive-site.conf) with its
  [text output](examples/sample-output.txt) and [SARIF](examples/sample.sarif).
- [`examples/github-code-scanning.yml`](examples/github-code-scanning.yml):
  GitHub Actions workflow that uploads SARIF to code scanning.
- [`examples/github-annotations.yml`](examples/github-annotations.yml): inline
  pull request annotations without code scanning.

### GitHub code scanning

```yaml
permissions:
  contents: read
  security-events: write
steps:
  - uses: actions/checkout@v4
  - uses: actions/setup-python@v5
    with:
      python-version: "3.12"
  - run: pip install "git+https://github.com/saizul/nginx-wp-lint.git@v0.1.0"
  - run: nginx-wp-lint nginx/ --prefix nginx/ -f sarif -o nginx-wp-lint.sarif --fail-on never
  - uses: github/codeql-action/upload-sarif@v3
    with:
      sarif_file: nginx-wp-lint.sarif
      category: nginx-wp-lint
```

Findings then appear under Security > Code scanning and on pull requests. Paths
in SARIF are relative to the working directory (use `--base` to change that),
which is what GitHub expects after `actions/checkout`.

To adopt the linter on an existing repository without fixing everything at
once, commit a baseline (see [Baselines](#baselines)) and add
`--baseline .nginx-wp-lint-baseline.json` to the command above.

### Pre-deploy check on a server

```bash
nginx -t && nginx-wp-lint /etc/nginx --fail-on high && systemctl reload nginx
```

### As a library

```python
from nginx_wp_lint import lint_paths, lint_string

result = lint_paths(["/etc/nginx"])
for f in result.findings:
    print(f.rule_id, f.severity.value, f.file, f.line, f.message)

lint_string("server { listen 80; autoindex on; }").findings
```

## Testing

```console
$ python -m pip install -e ".[dev]"
$ ruff check .
$ pytest
```

The suite parses and lints the fixture configurations in `tests/fixtures/`: a
hardened multi-file setup that must stay clean, a dozen broken site files
each with the exact set of rules it must trigger, include trees (globs,
missing files, cycles, includes inside locations), syntax errors and config
files. Location matching is tested with cases modelled on the nginx
documentation.

## Limitations

- **Static analysis only.** The linter does not run nginx, PHP or a browser, and
  it does not know which files exist on disk. "Would be served" means "served
  if the file exists". Run `nginx -t` as well; this tool does not check every
  directive's syntax.
- **Variables are not evaluated** (other than URI tests in `if`), `map` results
  are unknown, and `rewrite ... last` inside a location makes the outcome
  "unknown".
- **Regexes run in Python's `re`**, after translating PCRE named groups. PCRE
  features Python lacks (for example possessive quantifiers before Python
  3.11, or `\K`) make that location ignored for matching.
- **WordPress detection is simple**: every server block that handles PHP is
  checked with the WordPress rules. Disable rules per file or block for other
  PHP applications.
- **Unreadable includes** silence the rules that depend on them (reported once
  as `NWL090`). Lint on the server, or keep the snippets in the repository and
  pass `--prefix`.
- **Module directives**: headers-more (`more_set_headers`) and brotli are
  understood; other third-party modules are parsed but not interpreted.
- **SARIF** output follows the 2.1.0 specification as used by GitHub code
  scanning; other SARIF consumers may display some properties differently.

## Contributing

Bug reports with a (sanitised) configuration snippet, and new rules, are
welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues: see
[SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE). Copyright (c) 2026 Saizul Amin.

## Docker image

A multi-arch image (linux/amd64, linux/arm64) is published to GitHub Packages:

```bash
docker pull ghcr.io/saizul/nginx-wp-lint:latest
docker run --rm ghcr.io/saizul/nginx-wp-lint:latest --help
```

Mount the configuration read-only and lint it inside the container:

```bash
docker run --rm -v /etc/nginx:/etc/nginx:ro ghcr.io/saizul/nginx-wp-lint:latest /etc/nginx

# A repository checkout, with SARIF written back to the working directory
docker run --rm -v "$PWD:/work" ghcr.io/saizul/nginx-wp-lint:latest \
  nginx/ --prefix nginx/ -f sarif -o nginx-wp-lint.sarif
```

The working directory in the container is `/work`, so relative paths and
config files (`.nginx-wp-lint.toml`) are read from the mounted folder.
