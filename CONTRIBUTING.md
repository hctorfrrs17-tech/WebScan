# Contributing to WebScan

Thank you for considering a contribution to WebScan. This project is built around a simple principle: it should help authorized owners improve their own software without becoming a tool for unapproved testing.

## Before proposing a change

Please keep the authorization boundary intact. New checks must be low impact by default, must not add exploit payloads or bypass procedures, and must state the evidence they use plus their limitations. If a feature needs source code, deployment configuration, or authenticated behavior, design it around owner-provided evidence rather than unrestricted remote probing.

## Development workflow

Install dependencies with `pnpm install`, run the local app with `pnpm dev`, and complete `pnpm test`, `pnpm check`, and `pnpm build` before opening a pull request. Add tests for validation, data handling, severity ranking, report content, and prompt safety whenever you change those areas.

## Pull requests

Describe the user outcome, the safety impact, the test coverage, and any limitations that remain. Avoid claims that a change can find all vulnerabilities or fully secure a product. The maintainers may request changes when a proposal could enable unapproved scanning or increase risk to third parties.

## Responsible disclosure

Do not open a public issue with a reproducible security vulnerability. Follow [SECURITY.md](SECURITY.md) instead.
