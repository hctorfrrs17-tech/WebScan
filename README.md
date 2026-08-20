# WebScan

> **🛡️ A 15-agent, authorization-gated defensive security posture review for modern web apps.**

<p align="center">
  <strong>Own the target. Verify control. Add redacted evidence. Review what the agents observed. Fix with confidence.</strong>
</p>

<p align="center">
  <a href="#quick-start">Quick start</a> ·
  <a href="#15-agent-coverage">15 agents</a> ·
  <a href="#owner-evidence">Owner evidence</a> ·
  <a href="#real-controlled-audit">Real audit</a> ·
  <a href="#exports">Exports</a>
</p>

![WebScan’s authorization-gated workspace, including the optional redacted owner-evidence intake](assets/webscan-authorized-workspace.webp)

![WebScan’s report interface with posture score, agent readout, local history, and export formats](assets/webscan-report-overview.webp)

## ✨ What is WebScan?

WebScan coordinates **15 defensive agents** to help an authorized website owner turn observable security signals and carefully redacted owner evidence into a prioritized remediation plan. A review shows what was observed, how confident WebScan is, what remains outside coverage, how to verify a fix, and a safe coding-assistant brief for the next engineering step.

> **No account. No sign-in. No password.** WebScan begins with a website URL, an explicit authorization acknowledgement, and a one-time domain-verification file. Local review history stays in the browser on the device being used.

WebScan does **not** promise to find every vulnerability. No public-response review or limited code excerpt can make that guarantee. Instead, every agent reports its evidence source and limits so the owner can decide where a deeper authorized review is needed.

| 🧭 You provide | 🔎 The 15 agents review | 🧰 You receive |
| --- | --- | --- |
| A public website you own or are explicitly authorized to assess | Verified public response signals and, optionally, selected redacted source/configuration material | Score, agent coverage, evidence-backed findings, remediation guidance, verification criteria, and an AI coding prompt |

## 🚀 Quick start

WebScan is a local web application. You need **Git**, **Node.js 22 or later**, and **pnpm**. No API key, database, Docker setup, account, or production secret is required to run the project locally.

On macOS or Linux, run:

```bash
git clone https://github.com/hctorfrrs17-tech/WebScan.git
cd WebScan
pnpm install
pnpm dev
```

Then open [http://127.0.0.1:5173](http://127.0.0.1:5173). The `pnpm dev` command starts the frontend on port `5173` and its local API on port `8787` together. To stop both, return to the terminal and press `Ctrl+C`.

> **Windows:** Run the same commands inside [WSL](https://learn.microsoft.com/windows/wsl/install). The project’s development command uses standard shell environment-variable syntax, so WSL is the supported Windows path.

### The review flow

| Step | What happens |
| --- | --- |
| **01 — Confirm** | Enter a complete HTTP/HTTPS origin and confirm that you own it or have written authorization. |
| **02 — Add evidence** | Optionally select redacted source, dependency, CI, or deployment files so the owner-evidence agents can review real context. |
| **03 — Verify** | Publish the one-time token at `/.well-known/webscan-verification.txt`. |
| **04 — Review** | Run the bounded defensive review and inspect the score, agent coverage, limits, findings, and repair brief. |

## 🤖 15-agent coverage

The first five agents review a verified public response. The remaining agents become more useful when the owner selects redacted source or configuration evidence. Each agent is defensive only: it reports observed cues and remediation objectives, never exploit payloads or bypass instructions.

| # | Agent | Primary focus |
| ---: | --- | --- |
| 01 | **Transport agent** | HTTPS, redirects, HSTS, secure response delivery. |
| 02 | **Browser isolation agent** | CSP, framing, MIME protections, browser permissions. |
| 03 | **Session agent** | Visible cookie attributes, recovery and session boundaries. |
| 04 | **Authentication agent** | Owner-provided authentication-flow evidence. |
| 05 | **Authorization agent** | Roles, tenants, object ownership and server-side boundaries. |
| 06 | **Input safety agent** | Validation, encoding, unsafe rendering and upload-handling cues. |
| 07 | **Client exposure agent** | Client delivery, metadata, HTTP resources and public endpoint cues. |
| 08 | **API & error agent** | Route structure, response behavior and error-handling cues. |
| 09 | **Data privacy agent** | Referrer controls, data-minimization and lifecycle cues. |
| 10 | **Configuration hygiene agent** | Redacted configuration and environment-separation cues. |
| 11 | **Dependency agent** | Manifest, lockfile and package-hygiene cues. |
| 12 | **Supply-chain agent** | Build, CI and release workflow evidence. |
| 13 | **Deployment agent** | Runtime, headers and hosting-configuration evidence. |
| 14 | **Logging & recovery agent** | Logging, recovery and auditability cues. |
| 15 | **Storage & cryptography agent** | Storage, cryptography and data-lifecycle evidence. |

Read [AGENT_COVERAGE.md](AGENT_COVERAGE.md) for the complete evidence map and boundaries for every agent. [AGENT_EVIDENCE_POLICY.md](AGENT_EVIDENCE_POLICY.md) defines the concrete signal threshold required before an owner-evidence agent creates an actionable finding.

## 📎 Owner evidence

Owner evidence is **optional**, but it makes the authentication, authorization, input, dependency, supply-chain, deployment, logging, and storage agents substantially more useful. WebScan accepts up to eight small text files for the current review only, such as selected `.ts`/`.tsx`/`.js` files, `package.json`, lockfiles, CI workflows, redacted deployment configuration, or a safe `settings.txt` template.

| ✅ Appropriate evidence | ⛔ Never submit |
| --- | --- |
| Selected source files with the relevant control flow | Real `.env` files, credentials, tokens, private keys, connection strings, or personal data |
| `package.json`, lockfile, CI workflow, deployment template | Production secrets or complete raw database/application backups |
| Redacted configuration examples with placeholders | Any file you are not authorized to share |

The API rejects real environment-file names and common live-secret patterns. Evidence is used for the current in-memory review only; the report keeps a **summary** of files and types reviewed, not their contents.

## 📤 Exports

Every completed report can be exported without raw cookie values, credentials, or submitted evidence content. The export controls appear directly beside the report tabs.

| Format | Best for | Notes |
| --- | --- | --- |
| **JSON** | Automation, backup, structured ingestion | Includes findings, limits, agent coverage, and a safe evidence summary. |
| **Markdown** | GitHub issues, pull requests, project docs | Human-readable 15-agent readout and a copyable remediation brief. |
| **Print HTML** | Sharing or saving a PDF from the browser print dialog | Self-contained, print-ready report with scope and evidence-handling notices. |

## 🧪 Real controlled audit

The files below are **real output**, not a mock report. WebScan assessed a temporary website controlled solely for validation. The temporary page intentionally omitted several browser protections, set an incomplete test cookie, and referenced an HTTP asset. It was accompanied by five small redacted owner-evidence files containing deliberate, non-production signals such as a literal JWT signing value, client-controlled role input, unsafe HTML rendering, a wildcard CORS policy, and a privileged deployment setting. The normal `/.well-known/webscan-verification.txt` process completed before the assessment began.

### Result snapshot

| Result | Value |
| --- | --- |
| **Posture score** | **20 / 100** |
| **Grade** | **E** |
| **Attention items** | **17 evidence-backed findings** |
| **Agent coverage** | **15 / 15 agents completed** |
| **Owner evidence** | **5 redacted files**, summarized but not retained in the report |
| **Limits maintained** | No credentialed testing, exploitation, fuzzing, brute force, or denial-of-service testing |

### What the agents observed

| Agent area | Representative result from the controlled test |
| --- | --- |
| Transport and browser isolation | HSTS, CSP, MIME sniffing protection, and browser permissions controls were absent. |
| Session and privacy | The test cookie did not include the complete Secure/HttpOnly/SameSite posture, and Referrer-Policy was absent. The cookie value was never retained. |
| Client exposure | The page contained an HTTP resource reference. |
| Owner-evidence agents | The agents identified specific simulated signals and produced targeted corrections: move a literal JWT signing value to server-only configuration, reject client-supplied privilege values, remove or sanitize unsafe HTML rendering, replace wildcard CORS with an allowlist, pin dependencies, and run the container without privileged/root settings. No evidence excerpt was retained. |

### Resulting remediation prompt

The exact generated prompt and all evidence-backed findings are included in the downloadable artifacts. Each objective contains the observed signal, the required change, and its acceptance check; it does **not** ask a coding assistant to generically “review login”, “review storage”, or “review configuration”. Its key instruction style was:

```text
You are improving the security of the authorized web application.

Scope and evidence:
- This is a defensive remediation task based on a bounded WebScan review.
- Use the verified public-response evidence and the selected redacted owner evidence only.
- Respect the declared limits: no credentialed testing, exploitation, fuzzing, brute force, or denial-of-service testing.

Prioritized remediation objectives:
1. JWT signing value is embedded in source [Authentication agent; high]
   - Observed signal: Redacted owner evidence contains a JWT signing call with a literal value.
   - Required change: Read the signing value from a server-only secret at startup, reject startup when it is missing, and rotate the existing value before release.
   - Acceptance check: Add a startup test that fails without the secret and an integration test that accepts tokens signed with the configured replacement value only.
2. Client-supplied privilege value accepted [Authorization agent; high]
   - Observed signal: Redacted owner evidence assigns a role or privilege value directly from a request body.
   - Required change: Ignore client-supplied privilege fields and enforce role, tenant, and ownership boundaries server-side.
   - Acceptance check: Submit elevated role fields from an unprivileged client and confirm the protected action is denied.
3. Unsafe dynamic rendering or execution API used [Input safety agent; high]
   - Observed signal: Redacted owner evidence uses a dynamic execution or HTML-rendering API.
   - Required change: Remove the unsafe API or sanitize untrusted HTML with scripts, event attributes, and dangerous URL schemes disallowed.
   - Acceptance check: Test script tags, event attributes, and `javascript:` URLs and confirm none become active content.

Implementation constraints:
- Preserve existing product behavior and user flows.
- Do not add tracking, weaken authentication, hardcode secrets, or expose private data in logs.
- Add or update automated tests for every changed security behavior.
- Return the affected files, tests run, and remaining assumptions.
- Do not include exploit payloads, attack automation, or instructions for bypassing controls.
```

**Download the real controlled-audit artifacts:** [JSON](examples/controlled-audit-report.json) · [Markdown](examples/controlled-audit-report.md) · [Print HTML](examples/controlled-audit-report.html)

## 🔐 Safety boundary

WebScan is a **defensive, owner-authorized** review. It rejects local and private network destinations, metadata-style hosts, URL credentials, and non-standard ports. It resolves public DNS before requesting a target, uses an 8-second timeout, limits sampled HTML, and does not follow redirects.

| ✅ In scope | ⛔ Out of scope |
| --- | --- |
| Bounded public-response review of a verified domain you control | Unverified third-party targets, intranets, local networks, or arbitrary ports |
| Owner-selected, redacted evidence reviewed for the current assessment | Exploitation, credential attacks, bypasses, fuzzing, stealth scanning, brute force, or denial-of-service testing |
| Transparent evidence, coverage, confidence, limitations, and remediation criteria | Claims that a website has no vulnerabilities or that every vulnerability was found |

> A verification file confirms a minimal level of domain control. It is not a substitute for a formal scope agreement, a penetration test, or a complete application-security review.

## 🧱 Architecture

WebScan uses a React + TypeScript frontend, an Express + TypeScript backend, and structured findings. Reports are user-initiated and bounded; there is no background crawler, continuous scanner, account system, or cloud dashboard.

Read [ARCHITECTURE.md](ARCHITECTURE.md) for the authorization model and [AGENT_COVERAGE.md](AGENT_COVERAGE.md) for the 15-agent evidence model.

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
