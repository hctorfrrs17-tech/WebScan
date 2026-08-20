import { useMemo, useState } from "react";
import type { AssessmentReport, Finding, Severity, VerificationChallenge } from "../shared/types";

type ReviewHistoryItem = Pick<AssessmentReport, "id" | "target" | "hostname" | "score" | "grade" | "verifiedAt">;

const agentCatalog = [
  ["01", "Surface & transport", "HTTPS, redirects, headers, framing"],
  ["02", "Identity & sessions", "Cookies, recovery, session lifecycle"],
  ["03", "Access control", "Roles, tenants, object boundaries"],
  ["04", "Data protection", "Secrets, privacy, retention, leakage"],
  ["05", "Application exposure", "Inputs, errors, client delivery"],
  ["06", "Dependencies & supply chain", "Packages, lockfiles, release hygiene"],
  ["07", "Deployment posture", "Environment, CI, configuration"],
] as const;

const demoReport: AssessmentReport = {
  id: "demo",
  target: "https://example-product.test",
  hostname: "example-product.test",
  verifiedAt: "2026-08-20T09:30:00.000Z",
  score: 68,
  grade: "C",
  coverage: ["Verified public response", "Transport and response headers", "Visible cookie attributes", "Sampled HTML asset references", "Public technology hints"],
  limitations: ["No credentialed testing or authentication bypass attempts", "No active exploitation, fuzzing, brute force, or denial-of-service testing", "Access control, dependencies, and deployment require owner-provided source or configuration evidence"],
  specialists: agentCatalog.map(([id, label, focus], index) => ({ id, label, focus, state: index < 5 ? "complete" : "limited", findingCount: [1, 1, 0, 1, 1, 0, 0][index] })),
  findings: [
    { id: "d1", specialist: "Surface & transport", title: "Content Security Policy", severity: "medium", status: "attention", confidence: "high", evidence: "Content-Security-Policy was not present in the verified response.", impact: "The browser has no additional policy layer to contain some script injection impacts.", remediation: "Implement a restrictive, tested Content-Security-Policy and progressively remove broad script allowances.", verification: "Confirm a representative protected route returns an appropriate policy.", reference: "OWASP ASVS v5.0.0 — Encoding and Sanitization" },
    { id: "d2", specialist: "Identity & sessions", title: "Observed cookie hardening is incomplete", severity: "medium", status: "attention", confidence: "medium", evidence: "A state cookie was observed without every recommended browser attribute.", impact: "Sensitive state may have weaker protection in the browser.", remediation: "Review session and sensitive-state cookies; apply Secure, HttpOnly, and an appropriate SameSite setting.", verification: "Inspect cookies emitted by sign-in and recovery flows without retaining values.", reference: "OWASP ASVS v5.0.0 — Authentication and Session Management" },
    { id: "d3", specialist: "Application exposure", title: "Technology disclosure", severity: "low", status: "observe", confidence: "high", evidence: "A response technology banner was observed.", impact: "Technology details reduce discovery effort but are not a vulnerability by themselves.", remediation: "Remove unnecessary technology banners while preserving patching and inventory processes.", verification: "Inspect representative production responses for non-essential technology headers.", reference: "OWASP WSTG — Information Gathering" },
    { id: "d4", specialist: "Data protection", title: "Referrer policy", severity: "low", status: "attention", confidence: "high", evidence: "Referrer-Policy was not present in the verified response.", impact: "Sensitive paths or query parameters could be shared more broadly through browser referrer behavior.", remediation: "Set a reviewed Referrer-Policy subject to product requirements.", verification: "Confirm the policy on protected routes and external navigation paths.", reference: "OWASP ASVS v5.0.0 — Data Protection" },
    { id: "d5", specialist: "Surface & transport", title: "HTTPS transport observed", severity: "info", status: "pass", confidence: "high", evidence: "The verified target responded over HTTPS.", impact: "Encrypted transport was observed for the reviewed response.", remediation: "Keep HTTPS enforced and test redirects from HTTP.", verification: "Confirm all sensitive routes reject plaintext transport.", reference: "OWASP ASVS v5.0.0 — Communications Security" }
  ],
  generatedPrompt: "You are improving the security of an authorized web application.\n\nPrioritized remediation objectives:\n1. Add and test a restrictive Content-Security-Policy.\n2. Review state cookies and apply Secure, HttpOnly, and appropriate SameSite attributes.\n3. Add a reviewed Referrer-Policy and remove unnecessary technology banners.\n\nImplementation constraints:\n- Preserve existing product behavior and user flows.\n- Do not hardcode secrets or expose private data in logs.\n- Prefer server-side enforcement and framework-native controls.\n- Add automated tests for every changed security behavior.\n- Return the affected files, tests run, and remaining assumptions.\n- Do not include exploit payloads, bypass instructions, or attack automation."
};

function scoreGradeClass(grade: string) {
  return `grade grade--${grade.toLowerCase()}`;
}

function severityWeight(severity: Severity) {
  return { critical: 5, high: 4, medium: 3, low: 2, info: 1 }[severity];
}

function Icon({ name }: { name: "radar" | "shield" | "terminal" | "book" | "arrow" | "lock" | "copy" | "check" | "spark" }) {
  const paths = {
    radar: <><circle cx="12" cy="12" r="8" /><path d="M12 4v8l5 3" /><path d="M4 12h2" /></>,
    shield: <><path d="M12 3 19 6v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6l7-3Z" /><path d="m9 12 2 2 4-5" /></>,
    terminal: <><path d="m5 7 4 4-4 4" /><path d="M12 17h7" /></>,
    book: <><path d="M4 5.5A2.5 2.5 0 0 1 6.5 3H11v17H6.5A2.5 2.5 0 0 0 4 22Z" /><path d="M20 5.5A2.5 2.5 0 0 0 17.5 3H13v17h4.5A2.5 2.5 0 0 1 20 22Z" /></>,
    arrow: <><path d="M5 12h14" /><path d="m13 6 6 6-6 6" /></>,
    lock: <><rect x="5" y="10" width="14" height="11" rx="2" /><path d="M8 10V7a4 4 0 0 1 8 0v3" /></>,
    copy: <><rect x="9" y="9" width="10" height="11" rx="2" /><path d="M15 9V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h3" /></>,
    check: <path d="m5 12 4 4L19 6" />,
    spark: <><path d="m12 3 1.8 5.2L19 10l-5.2 1.8L12 17l-1.8-5.2L5 10l5.2-1.8Z" /><path d="m19 17 .8 2.2L22 20l-2.2.8L19 23l-.8-2.2L16 20l2.2-.8Z" /></>
  };
  return <svg className="icon" viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">{paths[name]}</svg>;
}

function SeverityChip({ severity }: { severity: Severity }) {
  return <span className={`severity severity--${severity}`}>{severity}</span>;
}

export default function App() {
  const [target, setTarget] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [challenge, setChallenge] = useState<VerificationChallenge | null>(null);
  const [report, setReport] = useState<AssessmentReport | null>(null);
  const [busy, setBusy] = useState<"challenge" | "verify" | "analyze" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [view, setView] = useState<"overview" | "findings" | "prompt">("overview");
  const [history, setHistory] = useState<ReviewHistoryItem[]>(() => {
    try { return JSON.parse(localStorage.getItem("webscan-review-history") ?? "[]") as ReviewHistoryItem[]; }
    catch { return []; }
  });

  const sortedFindings = useMemo(() => (report?.findings ?? []).slice().sort((a, b) => severityWeight(b.severity) - severityWeight(a.severity)), [report]);
  const attentionCount = report?.findings.filter((item) => item.status === "attention").length ?? 0;

  async function requestChallenge() {
    setError(null); setReport(null); setBusy("challenge");
    try {
      const normalizedTarget = target.trim().startsWith("http") ? target.trim() : `https://${target.trim()}`;
      setTarget(normalizedTarget);
      const response = await fetch("/api/challenges", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ target: normalizedTarget, authorizationConfirmed: authorized }) });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error);
      setChallenge(payload);
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Unable to create a verification challenge."); }
    finally { setBusy(null); }
  }

  async function verifyTarget() {
    if (!challenge) return; setError(null); setBusy("verify");
    try {
      const response = await fetch(`/api/challenges/${challenge.id}/verify`, { method: "POST" });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error);
      setChallenge({ ...challenge, instructions: `Verified at ${new Date(payload.verifiedAt).toLocaleTimeString()}. You can now run the bounded defensive review.` });
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Domain verification failed."); }
    finally { setBusy(null); }
  }

  async function runReview() {
    if (!challenge) return; setError(null); setBusy("analyze");
    try {
      const response = await fetch(`/api/challenges/${challenge.id}/analyze`, { method: "POST" });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error);
      rememberReport(payload); setView("overview");
    } catch (reason) { setError(reason instanceof Error ? reason.message : "The defensive review did not complete."); }
    finally { setBusy(null); }
  }

  async function copyPrompt() {
    if (!report) return;
    await navigator.clipboard.writeText(report.generatedPrompt);
    setCopied(true); window.setTimeout(() => setCopied(false), 1800);
  }

  function rememberReport(nextReport: AssessmentReport) {
    setReport(nextReport);
    setHistory((current) => {
      const next = [{ id: nextReport.id, target: nextReport.target, hostname: nextReport.hostname, score: nextReport.score, grade: nextReport.grade, verifiedAt: nextReport.verifiedAt }, ...current.filter((item) => item.id !== nextReport.id)].slice(0, 8);
      localStorage.setItem("webscan-review-history", JSON.stringify(next));
      return next;
    });
  }

  function exportReport() {
    if (!report) return;
    const content = JSON.stringify({ ...report, exportedAt: new Date().toISOString(), exportNotice: "This is a bounded defensive posture review. It does not prove the absence of vulnerabilities." }, null, 2);
    const url = URL.createObjectURL(new Blob([content], { type: "application/json" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = `webscan-${report.hostname}-${report.id.slice(0, 8)}.json`;
    link.click();
    URL.revokeObjectURL(url);
  }

  function loadDemo() { setChallenge(null); setError(null); rememberReport(demoReport); setView("overview"); }

  const verified = Boolean(challenge?.instructions.startsWith("Verified at"));

  return <main className="app-shell">
    <aside className="sidebar">
      <div className="brand"><span className="brand-mark"><Icon name="radar" /></span><span>WEBSCAN</span></div>
      <div className="side-label">WORKSPACE</div>
      <nav>
        <button className={view === "overview" ? "side-link active" : "side-link"} onClick={() => setView("overview")}><Icon name="radar" />Assessment</button>
        <button className={view === "findings" ? "side-link active" : "side-link"} onClick={() => setView("findings")} disabled={!report}><Icon name="shield" />Findings <span>{attentionCount || "—"}</span></button>
        <button className={view === "prompt" ? "side-link active" : "side-link"} onClick={() => setView("prompt")} disabled={!report}><Icon name="terminal" />Repair prompt</button>
      </nav>
      <div className="side-bottom">
        <a href="#method"><Icon name="book" /> Method & limits</a>
        <div className="safety-rail"><Icon name="lock" /><span>Owner-authorized reviews only</span></div>
      </div>
    </aside>

    <section className="content">
      <header className="topbar">
        <div><span className="eyebrow">DEFENSIVE POSTURE REVIEW</span><span className="status-dot">SYSTEM READY</span></div>
        <div className="topbar-right"><span className="version">ASVS-ALIGNED / 0.1</span><button className="ghost-button" onClick={loadDemo}>Explore demo <Icon name="arrow" /></button></div>
      </header>

      {!report && <section className="intro-grid">
        <div className="intro-copy">
          <div className="section-tag"><span className="pulse" /> Authorization-gated security review</div>
          <h1>See what your web app is <em>showing</em> to the world.</h1>
          <p>WebScan coordinates specialist reviews across your public surface, identity design, data handling, dependencies, and deployment posture—then turns evidence into a clear remediation plan.</p>
          <div className="intro-stats"><div><strong>07</strong><span>specialist lenses</span></div><div><strong>0</strong><span>exploit attempts</span></div><div><strong>1</strong><span>owner consent gate</span></div></div>
        </div>
        <div className="scope-card">
          <div className="scope-header"><span>ASSESSMENT BOUNDARY</span><Icon name="shield" /></div>
          <div className="scope-row"><span className="scope-yes"><Icon name="check" />Observed posture</span><span className="scope-yes"><Icon name="check" />Owner evidence</span></div>
          <div className="scope-row"><span className="scope-no">× No exploitation</span><span className="scope-no">× No credential attacks</span></div>
          <p>WebScan is a defensive review, not a penetration-testing replacement. It reports coverage and blind spots instead of claiming to find “everything”.</p>
        </div>
      </section>}

      {!report && <section className="assessment-panel">
        <div className="panel-heading"><div><span className="eyebrow">NEW REVIEW</span><h2>Prove control. Then inspect the posture.</h2></div><span className="step-count">01 / 03</span></div>
        <div className="target-form">
          <label htmlFor="target">Website origin</label>
          <div className="target-input"><span>https://</span><input id="target" value={target.replace(/^https:\/\//, "")} onChange={(event) => setTarget(event.target.value.replace(/^https:\/\//, ""))} placeholder="app.example.com" /><span className="cursor-mark">↗</span></div>
          <label className="consent"><input type="checkbox" checked={authorized} onChange={(event) => setAuthorized(event.target.checked)} /><span>I own this target or have written authorization to review it.</span></label>
          <button className="primary-button" disabled={!target || !authorized || busy !== null} onClick={requestChallenge}>
            {busy === "challenge" ? "Preparing boundary…" : "Create verification challenge"}<Icon name="arrow" />
          </button>
          <button className="text-button" onClick={loadDemo}>Or explore a safe demo report</button>
        </div>
        {error && <div className="error-box">{error}</div>}
        {challenge && <div className="challenge-box">
          <div className="challenge-top"><span className={verified ? "verified-pill" : "verify-pill"}>{verified ? "Verified target" : "Verification required"}</span><span>{challenge.hostname}</span></div>
          <p>{challenge.instructions}</p>
          {!verified && <><code>{challenge.token}</code><button className="secondary-button" onClick={verifyTarget} disabled={busy !== null}>{busy === "verify" ? "Checking verification…" : "Check verification file"}</button></>}
          {verified && <button className="primary-button run-button" onClick={runReview} disabled={busy !== null}>{busy === "analyze" ? "Running bounded review…" : "Run defensive review"}<Icon name="spark" /></button>}
        </div>}
      </section>}

      {!report && <section className="agent-section">
        <div className="section-heading"><div><span className="eyebrow">MULTI-LENS COVERAGE</span><h2>Seven agents. One accountable report.</h2></div><p>Every lens describes evidence, confidence, limits, and verification criteria. Source and deployment checks only activate with owner-provided material.</p></div>
        <div className="agent-grid">{agentCatalog.map(([index, label, focus]) => <article key={index} className="agent-card"><span>{index}</span><h3>{label}</h3><p>{focus}</p><i /></article>)}</div>
      </section>}

      {report && <section className="report-shell">
        <div className="report-title-row"><div><span className="eyebrow">VERIFIED REVIEW / {report.hostname}</span><h1>Security posture, <em>made actionable.</em></h1><p>Bounded review completed {new Date(report.verifiedAt).toLocaleString()}. The score reflects only the evidence examined.</p></div><div className={scoreGradeClass(report.grade)}><b>{report.grade}</b><span>{report.score}/100</span></div></div>
        <div className="report-nav"><div><button className={view === "overview" ? "selected" : ""} onClick={() => setView("overview")}>Overview</button><button className={view === "findings" ? "selected" : ""} onClick={() => setView("findings")}>Findings <span>{attentionCount}</span></button><button className={view === "prompt" ? "selected" : ""} onClick={() => setView("prompt")}>Repair prompt</button></div><div className="report-actions"><span>{history.length} local {history.length === 1 ? "review" : "reviews"}</span><button onClick={exportReport}>Export evidence <Icon name="arrow" /></button></div></div>

        {view === "overview" && <>
          <div className="metric-row"><div><span>POSTURE SCORE</span><strong>{report.score}<small>/100</small></strong><p>{report.grade === "A" || report.grade === "B" ? "Lower observed risk in this bounded review." : "Prioritized improvements are ready for review."}</p></div><div><span>ATTENTION ITEMS</span><strong>{attentionCount}</strong><p>Sorted by observed impact and confidence.</p></div><div><span>COVERAGE LIMIT</span><strong>{report.specialists.filter((item) => item.state === "complete").length}<small>/07</small></strong><p>Some lenses require source or configuration evidence.</p></div></div>
          <div className="report-columns"><div className="specialist-list"><div className="list-header"><h2>Specialist readout</h2><span>BOUNDARY: VERIFIED</span></div>{report.specialists.map((agent) => <div className="specialist-row" key={agent.id}><span className={`agent-state agent-state--${agent.state}`} /><div><b>{agent.label}</b><p>{agent.focus}</p></div><span className="finding-number">{agent.findingCount ? `${agent.findingCount} item${agent.findingCount > 1 ? "s" : ""}` : "clear / limited"}</span></div>)}</div>
          <div className="priority-card"><span className="eyebrow">FIRST MOVE</span><h2>{sortedFindings.find((item) => item.status === "attention")?.title ?? "Review complete"}</h2><p>{sortedFindings.find((item) => item.status === "attention")?.remediation ?? "No observed attention items were found in the available evidence."}</p><button className="secondary-button" onClick={() => setView("findings")}>Review finding <Icon name="arrow" /></button></div></div>
        </>}

        {view === "findings" && <section className="finding-section"><div className="finding-head"><div><span className="eyebrow">EVIDENCE-BASED FINDINGS</span><h2>What to improve first.</h2></div><span>{attentionCount} items need attention</span></div>{sortedFindings.map((item) => <FindingCard key={item.id} item={item} />)}</section>}

        {view === "prompt" && <section className="prompt-section"><div className="prompt-copy"><span className="eyebrow">VIBE-CODING REMEDIATION BRIEF</span><h2>Copy a safer implementation request.</h2><p>This prompt keeps the observed evidence, acceptance criteria, and non-regression constraints together. Review it before sharing it with any coding assistant.</p><button className="primary-button" onClick={copyPrompt}>{copied ? "Copied to clipboard" : "Copy repair prompt"}<Icon name={copied ? "check" : "copy"} /></button></div><pre>{report.generatedPrompt}</pre></section>}

        <div className="limit-banner"><Icon name="lock" /><div><b>Coverage is transparent by design.</b><p>{report.limitations.join(" · ")}</p></div></div>
      </section>}

      <section id="method" className="method-footer"><span>WEBSCAN METHOD</span><p>Guided by defensive verification principles from OWASP ASVS and the Web Security Testing Guide. WebScan never claims a complete absence of vulnerabilities.</p><a href="https://owasp.org/www-project-application-security-verification-standard/" target="_blank" rel="noreferrer">Read the reference <Icon name="arrow" /></a></section>
    </section>
  </main>;
}

function FindingCard({ item }: { item: Finding }) {
  return <article className={`finding-card finding-card--${item.status}`}><div className="finding-top"><div><SeverityChip severity={item.severity} /><span className="confidence">{item.confidence} confidence</span></div><span className="specialist-name">{item.specialist}</span></div><h3>{item.title}</h3><p className="finding-evidence"><b>Observed:</b> {item.evidence}</p><div className="finding-details"><div><span>WHY IT MATTERS</span><p>{item.impact}</p></div><div><span>REMEDIATION</span><p>{item.remediation}</p></div><div><span>VERIFY</span><p>{item.verification}</p></div></div>{item.reference && <small>{item.reference}</small>}</article>;
}
