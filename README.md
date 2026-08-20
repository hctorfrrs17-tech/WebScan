# WebScan

> **🛡️ An authorization-gated security posture review for modern web apps.**

<p align="center">
  <strong>Own the target. Verify control. Review the evidence. Fix with confidence.</strong>
</p>

<p align="center">
  <a href="#quick-start">Quick start</a> ·
  <a href="#real-controlled-audit">Real audit</a> ·
  <a href="#exports">Exports</a> ·
  <a href="#safety-boundary">Safety boundary</a>
</p>

![WebScan’s authorization-gated workspace with the StudySphere-inspired editorial interface](assets/webscan-authorized-workspace.webp)

![WebScan’s real report interface with score, findings, local history, and JSON/Markdown/HTML export options](assets/webscan-report-overview.webp)

## ✨ What is WebScan?

WebScan helps an authorized website owner turn safe, observable security signals into a clear remediation plan. It reviews a verified public response, explains what was observed, prioritizes the fixes, and creates a **safe coding-assistant brief** for applying those fixes without weakening the product.

> **No account. No sign-in. No password.** WebScan starts with a website URL, an explicit authorization acknowledgement, and a one-time domain-verification file. Your report history stays in the browser on the device you use.

| 🧭 You provide | 🔎 WebScan reviews | 🧰 You receive |
| --- | --- | --- |
| A public website you own or are explicitly authorized to assess | Transport, response headers, visible cookie attributes, sampled HTML references, and public technology hints | A score, evidence-based findings, remediation guidance, verification criteria, and an AI coding prompt |

## 🚀 Quick start

```bash
pnpm install
pnpm dev
```

Open `http://127.0.0.1:5173`. The frontend runs on port `5173` and proxies the local API to port `8787`.

### The review flow

| Step | What happens |
| --- | --- |
| **01 — Confirm** | Enter a complete HTTP/HTTPS origin and confirm that you own it or have written authorization. |
| **02 — Verify** | Publish the one-time token at `/.well-known/webscan-verification.txt`. |
| **03 — Review** | Run the bounded defensive review and inspect the score, coverage, limits, findings, and repair brief. |

## 🧩 Seven specialist lenses

WebScan separates what it observed from what needs additional owner-provided evidence. It does not pretend that a public response alone proves a complete security posture.

| Lens | Current focus | Evidence required |
| --- | --- | --- |
| **Surface & transport** | HTTPS, redirects, HSTS, browser response controls | Verified public response |
| **Identity & sessions** | Cookie attributes and session posture | Visible response plus owner evidence for full flows |
| **Access control** | Roles, tenants, object boundaries | Owner-provided routes or source |
| **Data protection** | Referrer policy, sensitive-data handling, secrets hygiene | Public signals plus owner evidence |
| **Application exposure** | CSP, MIME controls, client delivery, technology hints | Safe rendered response |
| **Dependencies & supply chain** | Packages, lockfiles, release controls | Owner-provided manifest and lockfile |
| **Deployment posture** | Environment separation, headers, CI controls | Owner-provided deployment configuration |

## 📤 Exports

Every completed report can be exported without raw cookie values or credentials. The export controls appear directly beside the report tabs.

| Format | Best for | Notes |
| --- | --- | --- |
| **JSON** | Automation, backup, structured ingestion | Includes the report, findings, limitations, and repair prompt. |
| **Markdown** | GitHub issues, pull requests, project docs | Human-readable findings and a copyable remediation brief. |
| **Print HTML** | Sharing or saving a PDF from the browser print dialog | Self-contained, print-ready report with the same bounded-scope notice. |

## 🧪 Real controlled audit

The following example is not a mock report. It is the output of a completed WebScan run against a **temporary website controlled solely for this validation**. The site intentionally omitted several browser protections, set an incomplete test cookie, and referenced an HTTP asset so that the defensive engine could produce evidence-backed results. It was verified with the normal `/.well-known/webscan-verification.txt` process before the assessment started.

### Result snapshot

| Result | Value |
| --- | --- |
| **Posture score** | **37 / 100** |
| **Grade** | **E** |
| **Attention items** | **7** |
| **Observed limitations** | No credentialed checks, exploitation, fuzzing, brute force, or denial-of-service testing |

### What WebScan observed

| Priority | Finding | What the controlled site demonstrated |
| --- | --- | --- |
| Medium | HSTS policy | `Strict-Transport-Security` was absent. |
| Medium | Content Security Policy | `Content-Security-Policy` was absent. |
| Medium | Cookie hardening | A test cookie lacked the complete Secure, HttpOnly, and SameSite posture. Its value was deliberately **not** kept in the report. |
| Medium | HTTP resource reference | The sampled HTML referenced an `http://` resource. |
| Low | Referrer policy | `Referrer-Policy` was absent. |
| Low | MIME sniffing protection | `X-Content-Type-Options` was absent. |
| Low | Permissions policy | `Permissions-Policy` was absent. |

### The resulting remediation prompt

The complete evidence and every finding are available in the export files below. This is the exact style of prompt WebScan generated from the controlled audit:

```text
You are improving the security of the authorized web application.

Scope and evidence:
- This is a defensive remediation task based on a bounded WebScan review.
- Coverage: verified public response; transport and response headers; visible cookie attributes; sampled HTML asset references; public technology hints.
- Limitations: no credentialed testing, authentication bypass attempts, active exploitation, fuzzing, brute force, or denial-of-service testing.

Prioritized remediation objectives:
1. Add a reviewed Strict-Transport-Security policy once all subdomains are ready for HTTPS.
2. Implement a restrictive, tested Content-Security-Policy and progressively remove broad script allowances.
3. Apply Secure, HttpOnly, and an appropriate SameSite setting to every sensitive state cookie.
4. Replace HTTP resource references with HTTPS sources and add CSP reporting or enforcement where appropriate.
5. Set reviewed Referrer-Policy, X-Content-Type-Options, and Permissions-Policy controls.

Implementation constraints:
- Preserve existing product behavior and user flows.
- Do not add tracking, weaken authentication, hardcode secrets, or expose private data in logs.
- Prefer framework-native security controls and server-side enforcement.
- Add or update automated tests for every changed security behavior.
- Return the affected files, tests run, and remaining assumptions.
- Do not include exploit payloads, attack automation, or instructions for bypassing controls.
```

**Download the real controlled-audit artifacts:** [JSON](examples/controlled-audit-report.json) · [Markdown](examples/controlled-audit-report.md) · [Print HTML](examples/controlled-audit-report.html)

## 🔐 Safety boundary

WebScan is a **defensive, owner-authorized** review. It rejects local and private network destinations, metadata-style hosts, URL credentials, and non-standard ports. It resolves public DNS before requesting a target, uses an 8-second timeout, limits sampled HTML, and does not follow redirects.

| ✅ In scope | ⛔ Out of scope |
| --- | --- |
| A bounded public-surface review of a domain you control | Unverified third-party targets, intranets, local networks, or arbitrary ports |
| Remediation guidance and safe development prompts | Exploitation, credential attacks, bypasses, fuzzing, stealth scanning, brute force, or denial-of-service testing |
| Transparent coverage and limitations | Claims that a website has no vulnerabilities |

> A verification file confirms a minimal level of domain control. It is not a substitute for a formal scope agreement, a penetration test, or a complete application-security review.

## 🧱 Architecture

WebScan uses a React + TypeScript frontend, an Express + TypeScript backend, and structured findings. Reports are user-initiated and bounded; there is no background crawler, continuous scanner, account system, or cloud dashboard.

Read [ARCHITECTURE.md](ARCHITECTURE.md) for the full authorization model, coverage map, and reporting rules.

## ✅ Quality checks

```bash
pnpm test
pnpm check
pnpm build
```

## 🤝 Contributing and reporting security issues

Contributions are welcome when they protect the defensive-only boundary. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. To report a project security concern privately, follow [SECURITY.md](SECURITY.md) rather than opening a public issue.

## 📚 References

WebScan uses the OWASP Application Security Verification Standard v5.0.0 as a guidance baseline and the OWASP Web Security Testing Guide for assessment context. These resources do not authorize testing on targets you do not control. [1] [2]

[1]: https://owasp.org/www-project-application-security-verification-standard/ "OWASP Application Security Verification Standard"
[2]: https://owasp.org/www-project-web-security-testing-guide/ "OWASP Web Security Testing Guide"
