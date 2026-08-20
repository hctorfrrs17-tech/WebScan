import { randomUUID } from "node:crypto";
import { isIP } from "node:net";
import { lookup } from "node:dns/promises";
import type { AssessmentReport, Finding, FindingStatus, OwnerEvidenceFile, Severity, SpecialistSummary, VerificationChallenge } from "../shared/types.js";
import { summarizeOwnerEvidence } from "./ownerEvidence.js";

const MAX_RESPONSE_BYTES = 240_000;

export type TargetRecord = {
  challenge: VerificationChallenge;
  verifiedAt?: string;
  ownerEvidence: OwnerEvidenceFile[];
};

export type SafeResponse = {
  url: string;
  status: number;
  headers: Headers;
  html: string;
};

const blockedHostnames = new Set(["localhost", "localhost.localdomain", "metadata.google.internal"]);

export function isPrivateAddress(value: string) {
  if (value === "::1" || value === "0.0.0.0") return true;
  if (value.includes(":")) return value.toLowerCase().startsWith("fc") || value.toLowerCase().startsWith("fd") || value.toLowerCase().startsWith("fe80");
  const [first, second] = value.split(".").map(Number);
  return first === 10 || first === 127 || first === 0 || (first === 169 && second === 254) || (first === 172 && second >= 16 && second <= 31) || (first === 192 && second === 168);
}

export function parsePublicTarget(input: string): URL {
  let target: URL;
  try {
    target = new URL(input.trim());
  } catch {
    throw new Error("Enter a complete HTTP or HTTPS website URL.");
  }
  if (!["http:", "https:"].includes(target.protocol)) throw new Error("Only HTTP and HTTPS website URLs can be assessed.");
  if (target.username || target.password) throw new Error("Credentials are not permitted in a target URL.");
  if (blockedHostnames.has(target.hostname.toLowerCase()) || target.hostname.endsWith(".local")) throw new Error("Local, metadata, and intranet targets are not permitted.");
  if (isIP(target.hostname) && isPrivateAddress(target.hostname)) throw new Error("Private network addresses are not permitted.");
  if (target.port && target.port !== "80" && target.port !== "443") throw new Error("WebScan only permits standard web ports.");
  return target;
}

export async function assertPublicHostname(target: URL) {
  const addresses = await lookup(target.hostname, { all: true, verbatim: true });
  if (!addresses.length || addresses.some((entry) => isPrivateAddress(entry.address))) {
    throw new Error("The target must resolve only to public internet addresses.");
  }
}

export function isReadableResponseType(type: string) {
  return type.includes("text/html") || type.startsWith("text/plain");
}

export async function fetchSafely(target: URL): Promise<SafeResponse> {
  await assertPublicHostname(target);
  const response = await fetch(target, {
    redirect: "manual",
    signal: AbortSignal.timeout(8_000),
    headers: { "User-Agent": "WebScan-Defensive-Review/0.1 (+authorized-owner-check)" }
  });
  const type = response.headers.get("content-type") ?? "";
  const readableText = isReadableResponseType(type);
  const html = readableText ? (await response.text()).slice(0, MAX_RESPONSE_BYTES) : "";
  return { url: target.toString(), status: response.status, headers: response.headers, html };
}

function finding(input: Omit<Finding, "id">): Finding {
  return { id: randomUUID(), ...input };
}

function headerFinding(options: {
  specialist: string;
  header: string;
  title: string;
  impact: string;
  remediation: string;
  reference: string;
  headers: Headers;
  severity?: Severity;
}): Finding {
  const present = Boolean(options.headers.get(options.header));
  return finding({
    specialist: options.specialist,
    title: options.title,
    severity: present ? "info" : options.severity ?? "medium",
    status: present ? "pass" : "attention",
    confidence: "high",
    evidence: present ? `${options.header} is present in the verified response.` : `${options.header} was not present in the verified response.`,
    impact: present ? "The observed control is available on this response." : options.impact,
    remediation: present ? "Retain the control and confirm it is applied consistently across sensitive routes." : options.remediation,
    verification: `Request a representative protected route and confirm the ${options.header} response header is present with an appropriate policy.`,
    reference: options.reference
  });
}

export function buildFindings(response: SafeResponse): Finding[] {
  const findings: Finding[] = [];
  const url = new URL(response.url);
  findings.push(finding({
    specialist: "Transport agent",
    title: url.protocol === "https:" ? "HTTPS transport observed" : "Target does not use HTTPS",
    severity: url.protocol === "https:" ? "info" : "high",
    status: url.protocol === "https:" ? "pass" : "attention",
    confidence: "high",
    evidence: `Verified target responded over ${url.protocol.replace(":", "").toUpperCase()}.`,
    impact: url.protocol === "https:" ? "Encrypted transport was observed for this response." : "Unencrypted transport can expose sessions, forms, and response content to network interception.",
    remediation: url.protocol === "https:" ? "Keep HTTPS enforced and test redirects from HTTP." : "Serve the application over HTTPS and redirect HTTP traffic to its secure equivalent.",
    verification: "Confirm that HTTP requests redirect to the HTTPS origin and that no sensitive route accepts plaintext transport.",
    reference: "OWASP ASVS v5.0.0 — Communications Security"
  }));
  findings.push(headerFinding({
    specialist: "Transport agent", header: "strict-transport-security", title: "HSTS policy", headers: response.headers,
    impact: "Without HSTS, returning visitors may be more exposed to protocol-downgrade risks.", remediation: "Set a reviewed Strict-Transport-Security policy once all subdomains are ready for HTTPS.", reference: "OWASP ASVS v5.0.0 — Communications Security", severity: "medium"
  }));
  findings.push(headerFinding({
    specialist: "Browser isolation agent", header: "content-security-policy", title: "Content Security Policy", headers: response.headers,
    impact: "A missing CSP removes an important browser-side containment layer against script injection impacts.", remediation: "Implement a restrictive, tested Content-Security-Policy and progressively remove broad script allowances.", reference: "OWASP ASVS v5.0.0 — Encoding and Sanitization", severity: "medium"
  }));
  findings.push(headerFinding({
    specialist: "Data privacy agent", header: "referrer-policy", title: "Referrer policy", headers: response.headers,
    impact: "Sensitive paths or query parameters can be disclosed to destinations through browser referrer behavior.", remediation: "Set a reviewed Referrer-Policy such as strict-origin-when-cross-origin, subject to product requirements.", reference: "OWASP ASVS v5.0.0 — Data Protection", severity: "low"
  }));
  findings.push(headerFinding({
    specialist: "Browser isolation agent", header: "x-content-type-options", title: "MIME sniffing protection", headers: response.headers,
    impact: "Without an explicit no-sniff directive, browsers may infer unexpected content types in edge cases.", remediation: "Set X-Content-Type-Options: nosniff for relevant responses and validate declared MIME types.", reference: "OWASP ASVS v5.0.0 — File Handling", severity: "low"
  }));
  findings.push(headerFinding({
    specialist: "Browser isolation agent", header: "permissions-policy", title: "Permissions policy", headers: response.headers,
    impact: "Browser features may be available more broadly than the application needs.", remediation: "Define a Permissions-Policy that disables browser features not required by the product.", reference: "OWASP ASVS v5.0.0 — Secure Coding", severity: "low"
  }));

  const server = response.headers.get("server") || response.headers.get("x-powered-by");
  findings.push(finding({
    specialist: "Client exposure agent",
    title: "Technology disclosure",
    severity: server ? "low" : "info",
    status: server ? "observe" : "pass",
    confidence: "high",
    evidence: server ? `Observed response technology hint: ${server}.` : "No Server or X-Powered-By response hint was observed.",
    impact: server ? "Technology details can reduce attacker discovery effort, although they are not a vulnerability by themselves." : "The response does not expose the common technology headers checked by this review.",
    remediation: server ? "Remove unnecessary response technology banners while maintaining patching and inventory processes." : "Continue to avoid unnecessary technology banners.",
    verification: "Inspect representative responses and confirm unnecessary technology-identifying headers are absent.",
    reference: "OWASP WSTG — Information Gathering"
  }));

  const cookies = response.headers.getSetCookie?.() ?? (response.headers.get("set-cookie") ? [response.headers.get("set-cookie")!] : []);
  if (cookies.length) {
    const missingAttributes = cookies.some((cookie) => !/;\s*secure/i.test(cookie) || !/;\s*httponly/i.test(cookie) || !/;\s*samesite=/i.test(cookie));
    findings.push(finding({
      specialist: "Session agent",
      title: missingAttributes ? "Observed cookie hardening is incomplete" : "Observed cookies include common hardening attributes",
      severity: missingAttributes ? "medium" : "info",
      status: missingAttributes ? "attention" : "pass",
      confidence: "medium",
      evidence: `${cookies.length} Set-Cookie response value(s) were observed in the verified response; values are intentionally not retained in the report.`,
      impact: missingAttributes ? "Session or state cookies without appropriate browser attributes may have weaker protection against common client-side threats." : "The observed response applies Secure, HttpOnly, and SameSite attributes to its cookies.",
      remediation: missingAttributes ? "Review each session and sensitive-state cookie; apply Secure, HttpOnly, and an appropriate SameSite setting where compatible with the authentication flow." : "Confirm this posture applies to every authentication and recovery flow.",
      verification: "Inspect cookies emitted by sign-in, recovery, and sensitive state transitions without exposing their values in logs.",
      reference: "OWASP ASVS v5.0.0 — Authentication and Session Management"
    }));
  } else {
    findings.push(finding({
      specialist: "Session agent", title: "No cookies observed on the reviewed response", severity: "info", status: "observe", confidence: "low",
      evidence: "The verified response did not set a cookie; authenticated and stateful flows were not exercised.", impact: "Session security cannot be concluded from this public response alone.", remediation: "Provide authenticated-flow evidence or source configuration for a fuller session review.", verification: "Review sign-in, recovery, and authenticated routes with owner-provided test evidence.", reference: "OWASP ASVS v5.0.0 — Authentication and Session Management"
    }));
  }

  const mixedContent = /(?:src|href)=["']http:\/\//i.test(response.html);
  findings.push(finding({
    specialist: "Client exposure agent", title: mixedContent ? "Potential HTTP resource reference" : "No HTTP asset reference observed in sampled HTML", severity: mixedContent ? "medium" : "info", status: mixedContent ? "attention" : "pass", confidence: response.html ? "medium" : "low",
    evidence: response.html ? (mixedContent ? "The sampled HTML contains at least one http:// resource reference." : "The sampled HTML did not contain an http:// resource reference.") : "The reviewed response was not HTML; client asset references were not inspected.",
    impact: mixedContent ? "Insecure subresource references can weaken a secure page or be blocked by browsers." : "This limited HTML sample did not expose an HTTP asset reference.",
    remediation: mixedContent ? "Replace HTTP resource references with HTTPS sources and add reporting or enforcement through CSP where appropriate." : "Continue enforcing secure asset delivery in templates and build output.",
    verification: "Review production pages in browser developer tools for mixed-content warnings.", reference: "OWASP ASVS v5.0.0 — Communications Security"
  }));
  return findings;
}

function evidenceFinding(input: Omit<Finding, "id">): Finding { return finding(input); }

export function buildOwnerEvidenceFindings(files: OwnerEvidenceFile[]): Finding[] {
  if (!files.length) return [];
  const content = files.map((file) => file.content).join("\n");
  const has = (pattern: RegExp) => pattern.test(content);
  const checks: Array<{ specialist: string; title: string; evidence: string; pattern: RegExp; severity: Severity; impact: string; remediation: string; verification: string; reference: string }> = [
    { specialist: "Authentication agent", title: "JWT signing value is embedded in source", evidence: "Redacted owner evidence contains a JWT signing call with a literal value.", pattern: /jwt\.sign\s*\([^,]+,\s*["'][^"']{4,}["']/i, severity: "high", impact: "A signing value embedded in source can be copied into builds or source-control history.", remediation: "Read the JWT signing value from a server-only secret at startup; reject startup when it is missing and rotate the existing value before release.", verification: "Add a startup test that fails without the secret and an integration test that accepts tokens signed with the configured replacement value only.", reference: "OWASP ASVS v5.0.0 — Authentication" },
    { specialist: "Authorization agent", title: "Client-supplied privilege value accepted", evidence: "Redacted owner evidence assigns a role or privilege value directly from a request body.", pattern: /(?:req|request)\.body\.(?:role|permission|isAdmin)|body\.(?:role|permission|isAdmin)/i, severity: "high", impact: "A client-controlled privilege field can allow privilege escalation if it is trusted at a protected action.", remediation: "Ignore client-supplied privilege fields for protected actions; derive roles server-side and enforce ownership or tenant checks before the state change.", verification: "Add tests that submit elevated role fields from an unprivileged client and confirm the protected action is denied.", reference: "OWASP ASVS v5.0.0 — Authorization" },
    { specialist: "Input safety agent", title: "Unsafe dynamic rendering or execution API used", evidence: "Redacted owner evidence uses a dynamic execution or HTML-rendering API.", pattern: /dangerouslySetInnerHTML|\.innerHTML\s*=|\beval\s*\(|new Function\s*\(/i, severity: "high", impact: "Dynamic execution or unsanitized HTML rendering can turn untrusted input into script execution.", remediation: "Remove the unsafe API where possible; otherwise sanitize untrusted HTML with a maintained sanitizer and keep scripts, event attributes, and dangerous URL schemes disallowed.", verification: "Add rendering tests with script tags, event attributes, and javascript: URLs and confirm none execute or render as active content.", reference: "OWASP ASVS v5.0.0 — Encoding and Sanitization" },
    { specialist: "API & error agent", title: "Stack trace returned to a client", evidence: "Redacted owner evidence sends an error stack in a response payload.", pattern: /(?:res|response)\.(?:json|send)\s*\([^)]*\.stack|stack\s*:\s*(?:err|error)\.stack/i, severity: "medium", impact: "Stack traces can disclose internal paths, packages, and implementation details to clients.", remediation: "Replace stack-trace responses with a stable error code and generic message; log diagnostic detail only through the server-side logging policy.", verification: "Add an error-path test that confirms client responses exclude stack, path, and dependency details.", reference: "OWASP WSTG — Error Handling" },
    { specialist: "Configuration hygiene agent", title: "Wildcard CORS policy configured", evidence: "Redacted owner evidence configures a wildcard CORS origin.", pattern: /origin\s*:\s*["']\*["']|Access-Control-Allow-Origin["']?\s*[:,]\s*["']\*["']/i, severity: "medium", impact: "A wildcard cross-origin policy can expose browser-readable responses more broadly than intended.", remediation: "Replace the wildcard with an explicit allowlist of trusted origins and keep credentialed requests disabled unless a reviewed product flow requires them.", verification: "Add tests that allow each approved origin and reject an unapproved origin, including credentialed preflight behavior.", reference: "OWASP ASVS v5.0.0 — Secure Coding" },
    { specialist: "Dependency agent", title: "Unbounded dependency version range", evidence: "Redacted owner evidence contains a latest, wildcard, or early 0.x dependency range.", pattern: /"(?:latest|\*)"|"\^[\s]*0\./i, severity: "medium", impact: "Unbounded or early-version ranges make dependency changes harder to review and reproduce.", remediation: "Replace the range with a reviewed stable version, commit the lockfile, and update through a tested dependency-review process.", verification: "Add CI validation that requires a lockfile and fails if production dependencies use latest or wildcard ranges.", reference: "OWASP ASVS v5.0.0 — Dependency Management" },
    { specialist: "Supply-chain agent", title: "Privileged or unpinned workflow installation pattern", evidence: "Redacted owner evidence contains pull_request_target or a remote installer pipe.", pattern: /pull_request_target|curl\s+[^\n|]+\|\s*(?:sh|bash)/i, severity: "high", impact: "Privileged pull-request workflows or remote installer pipes can execute unreviewed code in the build environment.", remediation: "Replace the privileged trigger with an unprivileged pull-request workflow and pin reviewed actions or installer checksums instead of piping remote content to a shell.", verification: "Add a workflow policy test that rejects pull_request_target and curl-pipe-shell patterns in CI configuration.", reference: "OWASP ASVS v5.0.0 — Secure Development" },
    { specialist: "Deployment agent", title: "Privileged container runtime configured", evidence: "Redacted owner evidence enables privileged or root container execution.", pattern: /privileged\s*:\s*true|runAsNonRoot\s*:\s*false|user\s*:\s*root/i, severity: "high", impact: "A privileged or root runtime increases the impact of a service compromise.", remediation: "Run the service as a dedicated non-root user, remove privileged mode, and drop unnecessary Linux capabilities in the deployment configuration.", verification: "Add a deployment policy check that rejects privileged mode, root user, and runAsNonRoot: false.", reference: "OWASP ASVS v5.0.0 — Configuration" },
    { specialist: "Logging & recovery agent", title: "Sensitive field written to logs", evidence: "Redacted owner evidence logs a password, token, secret, or recovery artifact.", pattern: /(?:console\.(?:log|error|warn)|logger\.[a-z]+)\s*\([^\n]*(?:password|token|secret|recovery)/i, severity: "high", impact: "Sensitive values in logs can persist beyond the session and expand who can access them.", remediation: "Remove the sensitive field from the log call, replace it with a non-sensitive event identifier, and apply a central redaction policy before log transport.", verification: "Add a logging test that exercises the flow and asserts password, token, secret, and recovery values never appear in captured logs.", reference: "OWASP ASVS v5.0.0 — Logging" },
    { specialist: "Storage & cryptography agent", title: "Deprecated hash used for a password or secret", evidence: "Redacted owner evidence uses MD5 or SHA-1 in a password or secret-handling context.", pattern: /(?:createHash\s*\(\s*["'](?:md5|sha1)["']|\b(?:md5|sha1)\s*\([^)]*(?:password|secret))/i, severity: "high", impact: "MD5 and SHA-1 are not suitable password-protection primitives and can weaken stored-secret protection.", remediation: "Replace the deprecated hash with a maintained password-hashing API such as Argon2id or scrypt, use per-password salts, and migrate existing hashes at successful login.", verification: "Add tests that create and verify a new password hash with the approved algorithm and reject legacy MD5/SHA-1 password hashes.", reference: "OWASP ASVS v5.0.0 — Cryptography and Data Protection" }
  ];
  return checks.filter((check) => has(check.pattern)).map((check) => evidenceFinding({ specialist: check.specialist, title: check.title, severity: check.severity, status: "attention", confidence: "high", evidence: `${check.evidence} No source excerpt is retained in the report.`, impact: check.impact, remediation: check.remediation, verification: check.verification, reference: check.reference }));
}

export function specialistSummaries(findings: Finding[], ownerEvidenceProvided = false): SpecialistSummary[] {
  const catalog = [
    ["transport", "Transport agent", "HTTPS, redirects, HSTS and secure response delivery"],
    ["browser", "Browser isolation agent", "CSP, framing, MIME and browser permissions"],
    ["session", "Session agent", "Visible cookies and session posture"],
    ["auth", "Authentication agent", "Owner-provided authentication evidence"],
    ["authorization", "Authorization agent", "Owner-provided role, tenant and ownership evidence"],
    ["input", "Input safety agent", "Validation, encoding and unsafe-rendering cues"],
    ["client", "Client exposure agent", "Client delivery, metadata and HTTP-resource cues"],
    ["api", "API & error agent", "Route and error-handling evidence"],
    ["privacy", "Data privacy agent", "Referrer and sensitive-data handling cues"],
    ["config", "Configuration hygiene agent", "Redacted configuration template evidence"],
    ["dependencies", "Dependency agent", "Manifest and lockfile evidence"],
    ["supply-chain", "Supply-chain agent", "Build, CI and release evidence"],
    ["deployment", "Deployment agent", "Redacted runtime and hosting configuration"],
    ["logging", "Logging & recovery agent", "Logging and recovery-flow evidence"],
    ["storage", "Storage & cryptography agent", "Storage, cryptography and lifecycle evidence"]
  ] as const;
  return catalog.map(([id, label, focus], index) => {
    const specialistFindings = findings.filter((item) => item.specialist === label);
    const state = index < 5 || ownerEvidenceProvided ? "complete" : "limited";
    return { id, label, focus, state, findingCount: specialistFindings.filter((item) => item.status === "attention").length };
  });
}

function scoreFindings(findings: Finding[]) {
  const weight: Record<Severity, number> = { critical: 30, high: 20, medium: 12, low: 5, info: 0 };
  const deduction = findings.filter((item) => item.status === "attention").reduce((total, item) => total + weight[item.severity], 0);
  return Math.max(20, Math.min(100, 100 - deduction));
}

export function buildRemediationPrompt(report: Pick<AssessmentReport, "target" | "findings" | "coverage" | "limitations">) {
  const priorities = report.findings.filter((item) => item.status === "attention").map((item, index) => `${index + 1}. ${item.title} [${item.specialist}; ${item.severity}]\n   - Observed signal: ${item.evidence}\n   - Required change: ${item.remediation}\n   - Acceptance check: ${item.verification}`).join("\n") || "No evidence-backed attention findings were produced. Do not invent changes for generic subsystems; retain the declared coverage limits.";
  return `You are improving the security of the authorized web application at ${report.target}.\n\nScope and evidence:\n- This is a defensive remediation task based on a bounded WebScan review.\n- Coverage: ${report.coverage.join("; ")}\n- Limitations: ${report.limitations.join("; ")}\n\nPrioritized remediation objectives:\n${priorities}\n\nImplementation constraints:\n- Preserve existing product behavior and user flows.\n- Do not add tracking, weaken authentication, hardcode secrets, or expose private data in logs.\n- Prefer framework-native security controls and server-side enforcement.\n- Add or update automated tests for every changed security behavior.\n- Validate headers, cookies, error handling, and authorization boundaries where relevant.\n- Return a concise change summary, affected files, tests run, and any remaining assumptions.\n- Do not include exploit payloads, attack automation, or instructions for bypassing controls.`;
}

export function createReport(record: TargetRecord, response: SafeResponse): AssessmentReport {
  const evidenceSummary = summarizeOwnerEvidence(record.ownerEvidence);
  const findings = [...buildFindings(response), ...buildOwnerEvidenceFindings(record.ownerEvidence)];
  const score = scoreFindings(findings);
  const grade = score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "E";
  const coverage = ["Verified public response", "Transport and response headers", "Visible cookie attributes", "Sampled HTML asset references", "Public technology hints", evidenceSummary.ownerEvidenceProvided ? `${evidenceSummary.sourceFilesReviewed} redacted owner-evidence file(s), processed for this review only` : "Owner-evidence agents remain limited until redacted source or configuration files are supplied"];
  const limitations = ["No credentialed testing or authentication bypass attempts", "No active exploitation, fuzzing, brute force, or denial-of-service testing", evidenceSummary.ownerEvidenceProvided ? "Source review is limited to the selected redacted excerpts supplied by the owner" : "Authentication, authorization, dependencies, deployment, logging, and storage agents require owner-provided redacted evidence"];
  const core = { target: record.challenge.target, findings, coverage, limitations };
  return {
    id: record.challenge.id,
    target: record.challenge.target,
    hostname: record.challenge.hostname,
    verifiedAt: record.verifiedAt ?? new Date().toISOString(),
    score,
    grade,
    coverage,
    limitations,
    specialists: specialistSummaries(findings, evidenceSummary.ownerEvidenceProvided),
    evidenceSummary,
    findings,
    generatedPrompt: buildRemediationPrompt(core)
  };
}
