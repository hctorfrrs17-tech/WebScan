# WebScan: defensive assessment architecture

WebScan is an **authorization-gated security posture review** for websites. It is not an offensive scanner, a penetration-testing replacement, or a guarantee that a website has no vulnerabilities. Its purpose is to help an owner understand observable security gaps, review their code and configuration safely, prioritize remediation, and prepare an implementation brief for their development workflow.

## Authorization boundary

Every assessment is bound to a target the user controls. The product requires the user to attest that they own the domain or have written authorization. The product design supports a domain-verification challenge and an optional repository connection. Until verification succeeds, the interface may only run a non-invasive preview over a user-provided sample; it must not initiate target requests.

WebScan does not perform credential attacks, endpoint fuzzing, exploitation, denial-of-service testing, content brute forcing, bypass attempts, stealth scanning, or actions against third-party targets. It never requests passwords or production secrets.

## Assessment model

The initial product combines a safe public-surface assessment with a richer source-review mode. Public checks are limited to low-impact observations such as HTTPS posture, response security headers, cookie attributes visible in supplied evidence, public metadata, client-side dependency indicators, and deployment configuration supplied by the owner. Source-review mode examines files selected by the owner for insecure patterns, dependency hygiene, secrets exposure, authorization design, session practices, logging, and error handling.

| Specialist | Primary responsibility | Evidence source |
| --- | --- | --- |
| Surface & transport | HTTPS, redirects, headers, CSP, framing, browser protections | Authorized public response or submitted headers |
| Identity & sessions | Authentication, recovery, session lifecycle, cookie policy, MFA readiness | Owner-provided configuration or source |
| Access control | Role boundaries, tenant isolation, object ownership checks | Source, route definitions, owner-provided test plan |
| Data protection | Secrets, sensitive-data lifecycle, encryption and retention cues | Source, environment templates, selected logs |
| Application exposure | Error handling, input validation, unsafe client patterns, public metadata | Source and safe rendered-page observations |
| Dependencies & supply chain | Dependency freshness, lockfile signals, build and release hygiene | Owner-provided manifest and lockfile |
| Deployment posture | Environment separation, security headers, CI checks, runtime configuration | Owner-provided deployment configuration |

Each specialist returns structured findings rather than exploit instructions. A finding contains severity, confidence, evidence, user impact, remediation objective, verification criterion, and an optional reference to an OWASP ASVS control. WebScan uses OWASP ASVS v5.0.0 as a guidance baseline and treats the OWASP Web Security Testing Guide as an educational reference, not as a license to test unverified targets.

## Reporting and coding-assistant prompt

The report orders findings by risk and confidence, states its coverage and blind spots, and separates observed evidence from recommendations. The generated development prompt tells a coding assistant which areas to change, expected secure behaviors, tests to add, and non-regression constraints. It must never include working exploit payloads or instructions for bypassing security controls.

## Initial delivery decision

The first version is a normal web application with a backend and database so that verified owners can manage targets and reports. It runs assessments as user-initiated bounded jobs; no continuous crawling or unrestricted autonomous scanning is included. This keeps the workload appropriate for managed hosting and makes the safety boundary enforceable. Broader continuous monitoring or any workflow requiring custom security tooling would require a separate architecture and explicit owner controls.

## References

- OWASP Application Security Verification Standard v5.0.0: https://owasp.org/www-project-application-security-verification-standard/
- OWASP Web Security Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
