# Security policy

## Supported versions

Security fixes are made for the latest release.

| Version | Supported |
|---|---|
| 0.1.x | yes |

## Reporting a vulnerability in nginx-wp-lint

Please do not open a public issue for security problems in the tool itself.
Use GitHub's
[private vulnerability reporting](https://github.com/saizul/nginx-wp-lint/security/advisories/new)
for this repository instead, with the version and steps to reproduce. You
should get a reply within a week.

Examples: a configuration file that makes the linter read files outside the
include paths it was asked to follow, execute anything, or hang.

## A rule missed a real exposure

A false negative in a security rule (for example a configuration that serves
`.git/` without NWL003 firing) is a bug, not a vulnerability in this project.
Open a normal issue with a sanitised configuration. Do not include real host
names or anything that identifies a live, still vulnerable site.

## What the linter does with your configuration

It only reads files: the paths you pass and the files they `include`. It does
not execute anything, does not contact the network and does not modify files.
Reports can contain paths and server names from your configuration; treat
SARIF and JSON output as internal documents.
