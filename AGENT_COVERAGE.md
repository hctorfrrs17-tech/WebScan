# WebScan 15-agent coverage model

WebScan coordinates 15 **defensive agents**. Each agent has a narrow purpose, a declared evidence source, and an explicit boundary. The system does not claim to find every vulnerability or replace an authorized professional security assessment.

## Evidence boundary

The public-response agents run only after domain verification. The owner-evidence agents operate on material manually supplied by the owner, such as selected source files, `package.json`, lockfiles, deployment configuration, CI workflow files, and redacted environment examples. Evidence is processed for the current review only and is not included verbatim in the generated report.

Owners must not submit real credentials, private keys, live connection strings, session tokens, personal data, or production `.env` files. WebScan blocks common secret patterns and sensitive filenames before an evidence bundle is accepted.

## Agent roster

| # | Agent | Primary evidence | Defensive focus |
| ---: | --- | --- | --- |
| 01 | Transport agent | Verified public response | HTTPS, redirects, HSTS, and secure response delivery. |
| 02 | Browser isolation agent | Verified headers and sampled HTML | CSP, framing controls, browser permissions, MIME protections. |
| 03 | Session agent | Visible cookies and owner-provided auth evidence | Cookie attributes, session boundaries, recovery-flow posture. |
| 04 | Authentication agent | Owner-provided source and configuration | Credential handling, authentication flow structure, recovery design cues. |
| 05 | Authorization agent | Owner-provided routes and source | Role checks, tenancy cues, ownership boundaries, server-side enforcement signals. |
| 06 | Input-safety agent | Owner-provided source and sampled HTML | Validation, encoding, unsafe rendering, upload handling cues. |
| 07 | Client exposure agent | Sampled HTML and owner-provided client code | Mixed content, exposed endpoints, unsafe client-side patterns, public metadata. |
| 08 | API & error agent | Public response and owner-provided server code | Error leakage, unsafe defaults, response handling and route posture. |
| 09 | Data privacy agent | Headers and owner-provided data-flow notes | Referrer controls, data minimization, retention and sensitive-data handling cues. |
| 10 | Configuration hygiene agent | Redacted config templates | Placeholder discipline, unsafe defaults, production/dev separation, secret-handling cues. |
| 11 | Dependency agent | Manifest and lockfile | Dependency inventory, lifecycle-script visibility, stale or unpinned version signals. |
| 12 | Supply-chain agent | CI and release configuration | Build provenance cues, release workflow controls, dependency-install practices. |
| 13 | Deployment agent | Redacted deployment configuration | Security headers, environment separation, runtime exposure, platform controls. |
| 14 | Logging & recovery agent | Owner-provided source and config | Sensitive logging cues, auditability, recovery and error-handling structure. |
| 15 | Storage & cryptography agent | Owner-provided source and architecture notes | Encryption-use cues, storage boundaries, key-reference handling, data lifecycle. |

## What the agents do not do

The agents do not use exploit payloads, authentication bypasses, credential attacks, brute force, fuzzing, stealth behavior, denial-of-service activity, arbitrary endpoint discovery, local-network access, or unverified third-party testing. A finding reports observed evidence, confidence, remediation objective, and a verification criterion instead of instructions to exploit a weakness.

## Expanded signal checks

The core agent boundaries remain unchanged, but each agent now checks a broader set of evidence-backed public-response and owner-evidence signals. See [AGENT_EXPANSION.md](AGENT_EXPANSION.md) for the exact expanded signal matrix and its evidence limits.

## References

- OWASP Application Security Verification Standard v5.0.0: https://owasp.org/www-project-application-security-verification-standard/
- OWASP Web Security Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
