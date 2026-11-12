# Contributing

Thanks for taking the time to improve nginx-wp-lint. Bug reports, false
positive and false negative reports, new rules and documentation fixes are all
welcome.

## Reporting a bug

Open an issue with:

- the command you ran and the output (`-f json` is easiest to read)
- your Python version and, if relevant, your nginx version (`nginx -v`)
- the smallest configuration that shows the problem

**Sanitise configurations before posting**: replace real host names with
`example.com`, and remove IP allow lists, upstream addresses, paths that
reveal customers, and anything that looks like a secret (basic auth files,
API keys in headers or `fastcgi_param`).

`nginx-wp-lint --print-tree your.conf` shows how the file was parsed and which
includes were found, which often explains a surprising result.

## Development setup

You need Python 3.9 or newer.

```console
$ git clone https://github.com/saizul/nginx-wp-lint.git
$ cd nginx-wp-lint
$ python -m venv .venv
$ . .venv/bin/activate
$ python -m pip install -e ".[dev]"
```

Then, before every commit:

```console
$ ruff check .
$ pytest
```

Both must pass; CI runs them on Python 3.9 to 3.12.

## Guidelines

- **No runtime dependencies** beyond the standard library (and `tomli` on old
  Pythons). PyYAML stays optional.
- **Model nginx, do not grep.** Use `resolve()` (which location handles a URI
  and what happens there), `effective()` (directive inheritance) and
  `effective_headers()` instead of searching the text.
- **Stay silent when unsure.** If an unreadable include or a variable could
  change the answer, do not report. A linter that cries wolf gets disabled.
- **Every rule needs** an ID, a kebab-case name, a severity, a category, a
  one-line summary, a concrete fix hint, a positive and a negative test, and a
  row in the README rule table (`--list-rules` output is the source of truth).
- **Fixture changes**: when a rule starts or stops firing on a file in
  `tests/fixtures/bad/`, update `EXPECTED` in `tests/test_fixtures.py`, and keep
  `tests/fixtures/good/` (and `examples/wordpress-hardened/`) lint clean.
- Rule IDs are never reused or renumbered.
- Keep lines within 100 characters and let `ruff check .` decide style.
- Add a line to the `Unreleased` section of `CHANGELOG.md` for anything a user
  would notice.

## Project layout

```text
src/nginx_wp_lint/
    lexer.py        tokenizer
    parser.py       directive tree, comments
    loader.py       include resolution
    model.py        servers, listen, inheritance, sizes, known includes
    locations.py    location matching and request outcomes
    headers.py      effective add_header / more_set_headers
    rules/          base.py plus security, headers, performance, tls,
                    wordpress, correctness, and the registry in __init__.py
    suppress.py     inline comments
    config.py       TOML/YAML settings
    linter.py       runs rules, applies settings and suppressions
    output/         text, json, sarif, github
    cli.py          command-line interface
examples/           hardened configuration, sample output, CI workflows
tests/              pytest suite and fixture configurations
```

## Adding a rule

1. Pick the module that fits, subclass `Rule`, set `id`, `name`, `severity`,
   `category`, `summary`, `hint` (and `http_level` for settings that belong in
   the http block), and implement `check(ctx)` yielding `self.finding(...)`.
2. Add the class to the module's `RULES` tuple.
3. Write tests in the matching `tests/test_rules_*.py` file, update fixture
   expectations, and add the README row.

## Pull requests

Keep pull requests focused on one change, describe what it does and why, and
mention anything you could not test. By contributing you agree that your work
is released under the MIT license of this project.
