# WebScan defensive posture review

> This is a bounded defensive posture review for https://3000-iqxvav6b63ryvbciag44g-50ce8d6f.us2.manus.computer/. It does not prove the absence of vulnerabilities and does not contain raw cookie values or private credentials.

| Target | Score | Grade | Attention items | Agents completed | Reviewed at |
| --- | ---: | --- | ---: | ---: | --- |
| https://3000-iqxvav6b63ryvbciag44g-50ce8d6f.us2.manus.computer/ | 20/100 | E | 17 | 15/15 | 2026-08-20T11:05:27.910Z |

## Evidence handling

5 redacted owner file(s) reviewed for this report only (.json, .ts, .yml). No file content is included in this export.

## Coverage

- Verified public response
- Transport and response headers
- Visible cookie attributes
- Sampled HTML asset references
- Public technology hints
- 5 redacted owner-evidence file(s), processed for this review only

## 15-agent readout

- **Transport agent:** complete; 1 finding. HTTPS, redirects, HSTS and secure response delivery
- **Browser isolation agent:** complete; 3 findings. CSP, framing, MIME and browser permissions
- **Session agent:** complete; 1 finding. Visible cookies and session posture
- **Authentication agent:** complete; 1 finding. Owner-provided authentication evidence
- **Authorization agent:** complete; 1 finding. Owner-provided role, tenant and ownership evidence
- **Input safety agent:** complete; 1 finding. Validation, encoding and unsafe-rendering cues
- **Client exposure agent:** complete; 1 finding. Client delivery, metadata and HTTP-resource cues
- **API & error agent:** complete; 1 finding. Route and error-handling evidence
- **Data privacy agent:** complete; 1 finding. Referrer and sensitive-data handling cues
- **Configuration hygiene agent:** complete; 1 finding. Redacted configuration template evidence
- **Dependency agent:** complete; 1 finding. Manifest and lockfile evidence
- **Supply-chain agent:** complete; 1 finding. Build, CI and release evidence
- **Deployment agent:** complete; 1 finding. Redacted runtime and hosting configuration
- **Logging & recovery agent:** complete; 1 finding. Logging and recovery-flow evidence
- **Storage & cryptography agent:** complete; 1 finding. Storage, cryptography and lifecycle evidence

## Limitations

- No credentialed testing or authentication bypass attempts
- No active exploitation, fuzzing, brute force, or denial-of-service testing
- Source review is limited to the selected redacted excerpts supplied by the owner

## Findings

### HTTPS transport observed

- **Agent:** Transport agent
- **Severity:** info
- **Status:** pass
- **Confidence:** high
- **Observed:** Verified target responded over HTTPS.
- **Why it matters:** Encrypted transport was observed for this response.
- **Remediation:** Keep HTTPS enforced and test redirects from HTTP.
- **Verify:** Confirm that HTTP requests redirect to the HTTPS origin and that no sensitive route accepts plaintext transport.
- **Reference:** OWASP ASVS v5.0.0 — Communications Security

### HSTS policy

- **Agent:** Transport agent
- **Severity:** medium
- **Status:** attention
- **Confidence:** high
- **Observed:** strict-transport-security was not present in the verified response.
- **Why it matters:** Without HSTS, returning visitors may be more exposed to protocol-downgrade risks.
- **Remediation:** Set a reviewed Strict-Transport-Security policy once all subdomains are ready for HTTPS.
- **Verify:** Request a representative protected route and confirm the strict-transport-security response header is present with an appropriate policy.
- **Reference:** OWASP ASVS v5.0.0 — Communications Security

### Content Security Policy

- **Agent:** Browser isolation agent
- **Severity:** medium
- **Status:** attention
- **Confidence:** high
- **Observed:** content-security-policy was not present in the verified response.
- **Why it matters:** A missing CSP removes an important browser-side containment layer against script injection impacts.
- **Remediation:** Implement a restrictive, tested Content-Security-Policy and progressively remove broad script allowances.
- **Verify:** Request a representative protected route and confirm the content-security-policy response header is present with an appropriate policy.
- **Reference:** OWASP ASVS v5.0.0 — Encoding and Sanitization

### Referrer policy

- **Agent:** Data privacy agent
- **Severity:** low
- **Status:** attention
- **Confidence:** high
- **Observed:** referrer-policy was not present in the verified response.
- **Why it matters:** Sensitive paths or query parameters can be disclosed to destinations through browser referrer behavior.
- **Remediation:** Set a reviewed Referrer-Policy such as strict-origin-when-cross-origin, subject to product requirements.
- **Verify:** Request a representative protected route and confirm the referrer-policy response header is present with an appropriate policy.
- **Reference:** OWASP ASVS v5.0.0 — Data Protection

### MIME sniffing protection

- **Agent:** Browser isolation agent
- **Severity:** low
- **Status:** attention
- **Confidence:** high
- **Observed:** x-content-type-options was not present in the verified response.
- **Why it matters:** Without an explicit no-sniff directive, browsers may infer unexpected content types in edge cases.
- **Remediation:** Set X-Content-Type-Options: nosniff for relevant responses and validate declared MIME types.
- **Verify:** Request a representative protected route and confirm the x-content-type-options response header is present with an appropriate policy.
- **Reference:** OWASP ASVS v5.0.0 — File Handling

### Permissions policy

- **Agent:** Browser isolation agent
- **Severity:** low
- **Status:** attention
- **Confidence:** high
- **Observed:** permissions-policy was not present in the verified response.
- **Why it matters:** Browser features may be available more broadly than the application needs.
- **Remediation:** Define a Permissions-Policy that disables browser features not required by the product.
- **Verify:** Request a representative protected route and confirm the permissions-policy response header is present with an appropriate policy.
- **Reference:** OWASP ASVS v5.0.0 — Secure Coding

### Technology disclosure

- **Agent:** Client exposure agent
- **Severity:** info
- **Status:** pass
- **Confidence:** high
- **Observed:** No Server or X-Powered-By response hint was observed.
- **Why it matters:** The response does not expose the common technology headers checked by this review.
- **Remediation:** Continue to avoid unnecessary technology banners.
- **Verify:** Inspect representative responses and confirm unnecessary technology-identifying headers are absent.
- **Reference:** OWASP WSTG — Information Gathering

### Observed cookie hardening is incomplete

- **Agent:** Session agent
- **Severity:** medium
- **Status:** attention
- **Confidence:** medium
- **Observed:** 1 Set-Cookie response value(s) were observed in the verified response; values are intentionally not retained in the report.
- **Why it matters:** Session or state cookies without appropriate browser attributes may have weaker protection against common client-side threats.
- **Remediation:** Review each session and sensitive-state cookie; apply Secure, HttpOnly, and an appropriate SameSite setting where compatible with the authentication flow.
- **Verify:** Inspect cookies emitted by sign-in, recovery, and sensitive state transitions without exposing their values in logs.
- **Reference:** OWASP ASVS v5.0.0 — Authentication and Session Management

### Potential HTTP resource reference

- **Agent:** Client exposure agent
- **Severity:** medium
- **Status:** attention
- **Confidence:** medium
- **Observed:** The sampled HTML contains at least one http:// resource reference.
- **Why it matters:** Insecure subresource references can weaken a secure page or be blocked by browsers.
- **Remediation:** Replace HTTP resource references with HTTPS sources and add reporting or enforcement through CSP where appropriate.
- **Verify:** Review production pages in browser developer tools for mixed-content warnings.
- **Reference:** OWASP ASVS v5.0.0 — Communications Security

### JWT signing value is embedded in source

- **Agent:** Authentication agent
- **Severity:** high
- **Status:** attention
- **Confidence:** high
- **Observed:** Redacted owner evidence contains a JWT signing call with a literal value. No source excerpt is retained in the report.
- **Why it matters:** A signing value embedded in source can be copied into builds or source-control history.
- **Remediation:** Read the JWT signing value from a server-only secret at startup; reject startup when it is missing and rotate the existing value before release.
- **Verify:** Add a startup test that fails without the secret and an integration test that accepts tokens signed with the configured replacement value only.
- **Reference:** OWASP ASVS v5.0.0 — Authentication

### Client-supplied privilege value accepted

- **Agent:** Authorization agent
- **Severity:** high
- **Status:** attention
- **Confidence:** high
- **Observed:** Redacted owner evidence assigns a role or privilege value directly from a request body. No source excerpt is retained in the report.
- **Why it matters:** A client-controlled privilege field can allow privilege escalation if it is trusted at a protected action.
- **Remediation:** Ignore client-supplied privilege fields for protected actions; derive roles server-side and enforce ownership or tenant checks before the state change.
- **Verify:** Add tests that submit elevated role fields from an unprivileged client and confirm the protected action is denied.
- **Reference:** OWASP ASVS v5.0.0 — Authorization

### Unsafe dynamic rendering or execution API used

- **Agent:** Input safety agent
- **Severity:** high
- **Status:** attention
- **Confidence:** high
- **Observed:** Redacted owner evidence uses a dynamic execution or HTML-rendering API. No source excerpt is retained in the report.
- **Why it matters:** Dynamic execution or unsanitized HTML rendering can turn untrusted input into script execution.
- **Remediation:** Remove the unsafe API where possible; otherwise sanitize untrusted HTML with a maintained sanitizer and keep scripts, event attributes, and dangerous URL schemes disallowed.
- **Verify:** Add rendering tests with script tags, event attributes, and javascript: URLs and confirm none execute or render as active content.
- **Reference:** OWASP ASVS v5.0.0 — Encoding and Sanitization

### Stack trace returned to a client

- **Agent:** API & error agent
- **Severity:** medium
- **Status:** attention
- **Confidence:** high
- **Observed:** Redacted owner evidence sends an error stack in a response payload. No source excerpt is retained in the report.
- **Why it matters:** Stack traces can disclose internal paths, packages, and implementation details to clients.
- **Remediation:** Replace stack-trace responses with a stable error code and generic message; log diagnostic detail only through the server-side logging policy.
- **Verify:** Add an error-path test that confirms client responses exclude stack, path, and dependency details.
- **Reference:** OWASP WSTG — Error Handling

### Wildcard CORS policy configured

- **Agent:** Configuration hygiene agent
- **Severity:** medium
- **Status:** attention
- **Confidence:** high
- **Observed:** Redacted owner evidence configures a wildcard CORS origin. No source excerpt is retained in the report.
- **Why it matters:** A wildcard cross-origin policy can expose browser-readable responses more broadly than intended.
- **Remediation:** Replace the wildcard with an explicit allowlist of trusted origins and keep credentialed requests disabled unless a reviewed product flow requires them.
- **Verify:** Add tests that allow each approved origin and reject an unapproved origin, including credentialed preflight behavior.
- **Reference:** OWASP ASVS v5.0.0 — Secure Coding

### Unbounded dependency version range

- **Agent:** Dependency agent
- **Severity:** medium
- **Status:** attention
- **Confidence:** high
- **Observed:** Redacted owner evidence contains a latest, wildcard, or early 0.x dependency range. No source excerpt is retained in the report.
- **Why it matters:** Unbounded or early-version ranges make dependency changes harder to review and reproduce.
- **Remediation:** Replace the range with a reviewed stable version, commit the lockfile, and update through a tested dependency-review process.
- **Verify:** Add CI validation that requires a lockfile and fails if production dependencies use latest or wildcard ranges.
- **Reference:** OWASP ASVS v5.0.0 — Dependency Management

### Privileged or unpinned workflow installation pattern

- **Agent:** Supply-chain agent
- **Severity:** high
- **Status:** attention
- **Confidence:** high
- **Observed:** Redacted owner evidence contains pull\_request\_target or a remote installer pipe. No source excerpt is retained in the report.
- **Why it matters:** Privileged pull-request workflows or remote installer pipes can execute unreviewed code in the build environment.
- **Remediation:** Replace the privileged trigger with an unprivileged pull-request workflow and pin reviewed actions or installer checksums instead of piping remote content to a shell.
- **Verify:** Add a workflow policy test that rejects pull\_request\_target and curl-pipe-shell patterns in CI configuration.
- **Reference:** OWASP ASVS v5.0.0 — Secure Development

### Privileged container runtime configured

- **Agent:** Deployment agent
- **Severity:** high
- **Status:** attention
- **Confidence:** high
- **Observed:** Redacted owner evidence enables privileged or root container execution. No source excerpt is retained in the report.
- **Why it matters:** A privileged or root runtime increases the impact of a service compromise.
- **Remediation:** Run the service as a dedicated non-root user, remove privileged mode, and drop unnecessary Linux capabilities in the deployment configuration.
- **Verify:** Add a deployment policy check that rejects privileged mode, root user, and runAsNonRoot: false.
- **Reference:** OWASP ASVS v5.0.0 — Configuration

### Sensitive field written to logs

- **Agent:** Logging & recovery agent
- **Severity:** high
- **Status:** attention
- **Confidence:** high
- **Observed:** Redacted owner evidence logs a password, token, secret, or recovery artifact. No source excerpt is retained in the report.
- **Why it matters:** Sensitive values in logs can persist beyond the session and expand who can access them.
- **Remediation:** Remove the sensitive field from the log call, replace it with a non-sensitive event identifier, and apply a central redaction policy before log transport.
- **Verify:** Add a logging test that exercises the flow and asserts password, token, secret, and recovery values never appear in captured logs.
- **Reference:** OWASP ASVS v5.0.0 — Logging

### Deprecated hash used for a password or secret

- **Agent:** Storage & cryptography agent
- **Severity:** high
- **Status:** attention
- **Confidence:** high
- **Observed:** Redacted owner evidence uses MD5 or SHA-1 in a password or secret-handling context. No source excerpt is retained in the report.
- **Why it matters:** MD5 and SHA-1 are not suitable password-protection primitives and can weaken stored-secret protection.
- **Remediation:** Replace the deprecated hash with a maintained password-hashing API such as Argon2id or scrypt, use per-password salts, and migrate existing hashes at successful login.
- **Verify:** Add tests that create and verify a new password hash with the approved algorithm and reject legacy MD5/SHA-1 password hashes.
- **Reference:** OWASP ASVS v5.0.0 — Cryptography and Data Protection

## AI coding remediation brief

```text
You are improving the security of the authorized web application at https://3000-iqxvav6b63ryvbciag44g-50ce8d6f.us2.manus.computer/.

Scope and evidence:
- This is a defensive remediation task based on a bounded WebScan review.
- Coverage: Verified public response; Transport and response headers; Visible cookie attributes; Sampled HTML asset references; Public technology hints; 5 redacted owner-evidence file(s), processed for this review only
- Limitations: No credentialed testing or authentication bypass attempts; No active exploitation, fuzzing, brute force, or denial-of-service testing; Source review is limited to the selected redacted excerpts supplied by the owner

Prioritized remediation objectives:
1. HSTS policy [Transport agent; medium]
   - Observed signal: strict-transport-security was not present in the verified response.
   - Required change: Set a reviewed Strict-Transport-Security policy once all subdomains are ready for HTTPS.
   - Acceptance check: Request a representative protected route and confirm the strict-transport-security response header is present with an appropriate policy.
2. Content Security Policy [Browser isolation agent; medium]
   - Observed signal: content-security-policy was not present in the verified response.
   - Required change: Implement a restrictive, tested Content-Security-Policy and progressively remove broad script allowances.
   - Acceptance check: Request a representative protected route and confirm the content-security-policy response header is present with an appropriate policy.
3. Referrer policy [Data privacy agent; low]
   - Observed signal: referrer-policy was not present in the verified response.
   - Required change: Set a reviewed Referrer-Policy such as strict-origin-when-cross-origin, subject to product requirements.
   - Acceptance check: Request a representative protected route and confirm the referrer-policy response header is present with an appropriate policy.
4. MIME sniffing protection [Browser isolation agent; low]
   - Observed signal: x-content-type-options was not present in the verified response.
   - Required change: Set X-Content-Type-Options: nosniff for relevant responses and validate declared MIME types.
   - Acceptance check: Request a representative protected route and confirm the x-content-type-options response header is present with an appropriate policy.
5. Permissions policy [Browser isolation agent; low]
   - Observed signal: permissions-policy was not present in the verified response.
   - Required change: Define a Permissions-Policy that disables browser features not required by the product.
   - Acceptance check: Request a representative protected route and confirm the permissions-policy response header is present with an appropriate policy.
6. Observed cookie hardening is incomplete [Session agent; medium]
   - Observed signal: 1 Set-Cookie response value(s) were observed in the verified response; values are intentionally not retained in the report.
   - Required change: Review each session and sensitive-state cookie; apply Secure, HttpOnly, and an appropriate SameSite setting where compatible with the authentication flow.
   - Acceptance check: Inspect cookies emitted by sign-in, recovery, and sensitive state transitions without exposing their values in logs.
7. Potential HTTP resource reference [Client exposure agent; medium]
   - Observed signal: The sampled HTML contains at least one http:// resource reference.
   - Required change: Replace HTTP resource references with HTTPS sources and add reporting or enforcement through CSP where appropriate.
   - Acceptance check: Review production pages in browser developer tools for mixed-content warnings.
8. JWT signing value is embedded in source [Authentication agent; high]
   - Observed signal: Redacted owner evidence contains a JWT signing call with a literal value. No source excerpt is retained in the report.
   - Required change: Read the JWT signing value from a server-only secret at startup; reject startup when it is missing and rotate the existing value before release.
   - Acceptance check: Add a startup test that fails without the secret and an integration test that accepts tokens signed with the configured replacement value only.
9. Client-supplied privilege value accepted [Authorization agent; high]
   - Observed signal: Redacted owner evidence assigns a role or privilege value directly from a request body. No source excerpt is retained in the report.
   - Required change: Ignore client-supplied privilege fields for protected actions; derive roles server-side and enforce ownership or tenant checks before the state change.
   - Acceptance check: Add tests that submit elevated role fields from an unprivileged client and confirm the protected action is denied.
10. Unsafe dynamic rendering or execution API used [Input safety agent; high]
   - Observed signal: Redacted owner evidence uses a dynamic execution or HTML-rendering API. No source excerpt is retained in the report.
   - Required change: Remove the unsafe API where possible; otherwise sanitize untrusted HTML with a maintained sanitizer and keep scripts, event attributes, and dangerous URL schemes disallowed.
   - Acceptance check: Add rendering tests with script tags, event attributes, and javascript: URLs and confirm none execute or render as active content.
11. Stack trace returned to a client [API & error agent; medium]
   - Observed signal: Redacted owner evidence sends an error stack in a response payload. No source excerpt is retained in the report.
   - Required change: Replace stack-trace responses with a stable error code and generic message; log diagnostic detail only through the server-side logging policy.
   - Acceptance check: Add an error-path test that confirms client responses exclude stack, path, and dependency details.
12. Wildcard CORS policy configured [Configuration hygiene agent; medium]
   - Observed signal: Redacted owner evidence configures a wildcard CORS origin. No source excerpt is retained in the report.
   - Required change: Replace the wildcard with an explicit allowlist of trusted origins and keep credentialed requests disabled unless a reviewed product flow requires them.
   - Acceptance check: Add tests that allow each approved origin and reject an unapproved origin, including credentialed preflight behavior.
13. Unbounded dependency version range [Dependency agent; medium]
   - Observed signal: Redacted owner evidence contains a latest, wildcard, or early 0.x dependency range. No source excerpt is retained in the report.
   - Required change: Replace the range with a reviewed stable version, commit the lockfile, and update through a tested dependency-review process.
   - Acceptance check: Add CI validation that requires a lockfile and fails if production dependencies use latest or wildcard ranges.
14. Privileged or unpinned workflow installation pattern [Supply-chain agent; high]
   - Observed signal: Redacted owner evidence contains pull_request_target or a remote installer pipe. No source excerpt is retained in the report.
   - Required change: Replace the privileged trigger with an unprivileged pull-request workflow and pin reviewed actions or installer checksums instead of piping remote content to a shell.
   - Acceptance check: Add a workflow policy test that rejects pull_request_target and curl-pipe-shell patterns in CI configuration.
15. Privileged container runtime configured [Deployment agent; high]
   - Observed signal: Redacted owner evidence enables privileged or root container execution. No source excerpt is retained in the report.
   - Required change: Run the service as a dedicated non-root user, remove privileged mode, and drop unnecessary Linux capabilities in the deployment configuration.
   - Acceptance check: Add a deployment policy check that rejects privileged mode, root user, and runAsNonRoot: false.
16. Sensitive field written to logs [Logging & recovery agent; high]
   - Observed signal: Redacted owner evidence logs a password, token, secret, or recovery artifact. No source excerpt is retained in the report.
   - Required change: Remove the sensitive field from the log call, replace it with a non-sensitive event identifier, and apply a central redaction policy before log transport.
   - Acceptance check: Add a logging test that exercises the flow and asserts password, token, secret, and recovery values never appear in captured logs.
17. Deprecated hash used for a password or secret [Storage & cryptography agent; high]
   - Observed signal: Redacted owner evidence uses MD5 or SHA-1 in a password or secret-handling context. No source excerpt is retained in the report.
   - Required change: Replace the deprecated hash with a maintained password-hashing API such as Argon2id or scrypt, use per-password salts, and migrate existing hashes at successful login.
   - Acceptance check: Add tests that create and verify a new password hash with the approved algorithm and reject legacy MD5/SHA-1 password hashes.

Implementation constraints:
- Preserve existing product behavior and user flows.
- Do not add tracking, weaken authentication, hardcode secrets, or expose private data in logs.
- Prefer framework-native security controls and server-side enforcement.
- Add or update automated tests for every changed security behavior.
- Validate headers, cookies, error handling, and authorization boundaries where relevant.
- Return a concise change summary, affected files, tests run, and any remaining assumptions.
- Do not include exploit payloads, attack automation, or instructions for bypassing controls.
```
