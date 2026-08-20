# WebScan

> **A defensive, authorization-gated security posture review for modern web applications.**

WebScan helps website owners turn observable security gaps into a clear remediation plan. It coordinates specialist lenses across transport, browser controls, sessions, data handling, application exposure, dependencies, and deployment posture—then produces evidence-based findings and a safe implementation prompt for coding assistants.

## Why WebScan

WebScan is designed for teams that build quickly and still want a clear, defensible security baseline. It does **not** claim to find every vulnerability, replace a professional penetration test, or test a target that has not been authorized. Instead, it makes its coverage, confidence, and blind spots explicit.

| WebScan does | WebScan does not do |
| --- | --- |
| Requires an owner authorization acknowledgement and a domain-verification challenge. | Scan local networks, metadata services, private IPs, intranets, arbitrary ports, or unverified third-party targets. |
| Reviews safe public-response signals such as HTTPS, headers, sampled HTML references, cookie attributes, and public technology hints. | Attempt exploitation, authentication bypasses, credential attacks, fuzzing, brute force, stealth scanning, or denial-of-service testing. |
| Lists source/dependency/deployment areas that need owner-provided evidence for a fuller review. | Claim a complete absence of vulnerabilities from a public-only check. |
| Produces prioritized remediation objectives and an AI coding prompt with non-regression constraints. | Generate exploit payloads, bypass instructions, or attack automation. |

## Product flow

1. Enter a public website origin and confirm that you own it or have written authorization.
2. Publish the one-time verification token at `/.well-known/webscan-verification.txt`.
3. Let WebScan perform its bounded, low-impact public-surface review.
4. Review the score, specialist coverage, observed evidence, remediation guidance, and verification criteria.
5. Copy the generated repair brief into a coding assistant after reviewing it yourself.

## Specialist coverage

| Lens | Current evidence source | Typical review focus |
| --- | --- | --- |
| Surface & transport | Verified public response | HTTPS, redirects, HSTS, browser response controls |
| Identity & sessions | Visible response behavior and owner evidence | Cookie attributes, recovery flows, session lifecycle |
| Access control | Owner-provided routes or source | Roles, tenancy, resource ownership boundaries |
| Data protection | Public signals and owner evidence | Referrer policy, sensitive-data lifecycle, secrets hygiene |
| Application exposure | Safe rendered response | CSP, MIME controls, client asset delivery, technology banners |
| Dependencies & supply chain | Owner-provided manifest and lockfile | Package hygiene, build and release controls |
| Deployment posture | Owner-provided configuration | Environment separation, security headers, CI checks |

## Safe by design

WebScan validates target URLs, rejects local/private destinations and non-standard ports, resolves public DNS before a request, uses an 8-second request timeout, limits sampled HTML, avoids credentials, and follows no redirects. The first release intentionally runs only a user-initiated bounded review; it does not include continuous crawling or unrestricted autonomous scanning.

> A domain-verification file proves a minimal level of control over a host. It is not a substitute for a formal authorization process, penetration-testing scope, or a complete security review.

## Local development

Requirements: Node.js 22+ and pnpm.

```bash
pnpm install
pnpm dev
```

Open `http://127.0.0.1:5173`. The frontend runs on port `5173` and proxies API requests to the local Express service on port `8787`.

### Quality checks

```bash
pnpm test
pnpm check
pnpm build
```

## Architecture

WebScan uses a React and TypeScript frontend, an Express and TypeScript backend, and a structured findings model. The current public-surface engine is deliberately deterministic and bounded. It is designed to feed a future owner-provided source-review workflow rather than act as an unrestricted scanner.

Read [ARCHITECTURE.md](ARCHITECTURE.md) for the authorization boundary, coverage model, limitations, and reporting rules.

## Standards and references

WebScan uses the **OWASP Application Security Verification Standard (ASVS) v5.0.0** as a guidance baseline, while the **OWASP Web Security Testing Guide (WSTG)** provides educational context for assessment categories. These references do not authorize testing against targets you do not control.

- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

## Contributing and security

Contributions are welcome when they preserve the defensive-only boundary. Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. Please use [SECURITY.md](SECURITY.md) to report a security concern privately rather than publishing an exploit in an issue.

## Status

WebScan is an early open-source foundation. The interface, target boundary, specialist model, report flow, remediation prompt, and automated safety checks are implemented. Future work should only extend source, dependency, or deployment coverage through explicit owner-provided evidence and maintain the same authorization limits.
