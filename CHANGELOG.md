# Changelog

All notable changes to WebScan are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-08-20

### Added

- An authorization-gated, defensive security posture review for public web applications.
- One-time domain-control verification through `/.well-known/webscan-verification.txt` before an assessment can start.
- Fifteen clearly scoped review areas covering transport, browser isolation, sessions, authentication, authorization, input handling, client exposure, API/error behavior, privacy, configuration, dependencies, supply chain, deployment, logging, and storage/cryptography.
- Bounded public-response review with DNS checks, private-network restrictions, standard-web-port restrictions, an eight-second request timeout, manual redirect handling, and sampled HTML processing.
- Optional intake for small, redacted owner evidence; submitted evidence is evaluated only for the current in-memory review and summarized rather than retained in the report.
- Evidence-backed remediation guidance with explicit impact, recommended change, and acceptance criteria for each relevant finding.
- A self-contained printable PDF report with posture score, scope, limitations, specialist readouts, and a defensive coding prompt.
- A responsive React workspace, a controlled demo report, documentation, and a contribution/security policy.
- Automated unit tests for target boundaries, owner-evidence handling, assessment behavior, and PDF export.

### Security

- WebScan is intentionally limited to owner-authorized defensive review. It does not perform credential attacks, authentication bypasses, exploitation, fuzzing, brute force, or denial-of-service testing.
- The product reports observed controls and explicit coverage limits; it does not claim to find every vulnerability or certify that a target is secure.

[0.1.0]: https://github.com/hctorfrrs17-tech/WebScan/releases/tag/v0.1.0
