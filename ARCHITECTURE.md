# WebScan: defensive assessment architecture

WebScan is an **authorization-gated security posture review** for websites. It is not an offensive scanner, a penetration-testing replacement, or a guarantee that a website has no vulnerabilities. Its purpose is to help an owner understand observable security gaps, review their code and configuration safely, prioritize remediation, and prepare an implementation brief for their development workflow.

## Authorization boundary

Every assessment is bound to a target the user controls. The product requires the user to attest that they own the domain or have written authorization, then publish a one-time token at `/.well-known/webscan-verification.txt`. Until verification succeeds, the interface may only run a non-invasive preview; it must not initiate target requests.

WebScan does not perform credential attacks, endpoint fuzzing, exploitation, denial-of-service testing, content brute forcing, bypass attempts, stealth scanning, or actions against third-party targets. It never requests passwords or production secrets.

## Assessment model

WebScan combines a safe public-surface review with an owner-evidence mode. The five public-response agents inspect low-impact signals such as HTTPS posture, response security headers, visible cookie attributes, public metadata, and sampled client asset references. Ten additional agents assess only redacted material selected by the owner: source snippets, manifests, lockfiles, CI workflows, deployment templates, and safe configuration examples.

The owner-evidence boundary permits up to eight small text files for the current in-memory review. Real environment files, private keys, common live-secret patterns, credentials, session tokens, personal data, and production database or application backups are blocked. The report stores only a file-count and extension summary, never an evidence excerpt.

WebScan's [15-agent coverage map](AGENT_COVERAGE.md) names the responsibility and evidence boundary for every agent. Every agent returns structured findings rather than exploit instructions. A finding contains severity, confidence, evidence, user impact, remediation objective, verification criterion, and an optional reference to an OWASP ASVS control. WebScan uses OWASP ASVS v5.0.0 as a guidance baseline and treats the OWASP Web Security Testing Guide as an educational reference, not as a license to test unverified targets.

## Reporting and coding-assistant prompt

The report orders findings by risk and confidence, states its coverage and blind spots, and separates observed evidence from recommendations. The generated development prompt tells a coding assistant which areas to change, expected secure behaviors, tests to add, and non-regression constraints. It must never include working exploit payloads or instructions for bypassing security controls.

## Initial delivery decision

The current version is a normal web application with a small backend and **no account system or database**. Domain-verification records and owner evidence exist only for the active service process; the browser keeps its local report-history metadata on the user’s device. Assessments are user-initiated bounded jobs; no continuous crawling or unrestricted autonomous scanning is included. This keeps the safety boundary enforceable. Broader monitoring or deeper source-analysis workflows would require a separate, explicitly authorized architecture.

## References

- OWASP Application Security Verification Standard v5.0.0: https://owasp.org/www-project-application-security-verification-standard/
- OWASP Web Security Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
