import type { AssessmentReport, Finding, SpecialistSummary } from "../shared/types";

function redactSensitiveText(value: string) {
  return value.replace(/\b(cookie|session|token|api[_-]?key|password|secret|authorization)\s*(?:=|:)\s*[^\s,;]+/gi, "$1=[redacted]");
}

function escapeHtml(value: string) {
  return redactSensitiveText(value).replace(/[&<>'"]/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", "\"": "&quot;" })[character] ?? character);
}

function reportPreamble(report: AssessmentReport) {
  return `This is a bounded defensive posture review for ${report.target}. It does not prove the absence of vulnerabilities and does not contain raw cookie values, owner-evidence contents, or private credentials.`;
}

function chunk<T>(items: T[], size: number) {
  return Array.from({ length: Math.ceil(items.length / size) }, (_, index) => items.slice(index * size, index * size + size));
}

function findingCard(item: Finding) {
  return `<article class="finding"><div class="finding-meta"><b>${escapeHtml(item.severity.toUpperCase())}</b><span>${escapeHtml(item.confidence)} confidence · ${escapeHtml(item.status)}</span></div><h3>${escapeHtml(item.title)}</h3><p><strong>Observed signal:</strong> ${escapeHtml(item.evidence)}</p><dl><div><dt>Why it matters</dt><dd>${escapeHtml(item.impact)}</dd></div><div><dt>Required change</dt><dd>${escapeHtml(item.remediation)}</dd></div><div><dt>Acceptance check</dt><dd>${escapeHtml(item.verification)}</dd></div></dl>${item.reference ? `<small>${escapeHtml(item.reference)}</small>` : ""}</article>`;
}

function agentReadout(agent: SpecialistSummary, index: number, allFindings: Finding[]) {
  const findings = allFindings.filter((item) => item.specialist === agent.label);
  const attention = findings.filter((item) => item.status === "attention");
  const controls = findings.filter((item) => item.status !== "attention");
  const result = attention.length
    ? `${attention.length} concrete evidence-backed attention finding${attention.length === 1 ? " requires" : "s require"} remediation.`
    : agent.state === "limited"
      ? "No actionable finding was produced because the evidence available to this agent is limited."
      : "No evidence-backed attention finding was produced by this agent for the reviewed material.";
  return `<section class="agent"><div class="agent-heading"><div><span class="agent-index">AGENT ${String(index + 1).padStart(2, "0")}</span><h3>${escapeHtml(agent.label)}</h3></div><div class="agent-state">${escapeHtml(agent.state.toUpperCase())}<br><small>${attention.length} attention</small></div></div><p class="agent-focus"><strong>Evidence scope:</strong> ${escapeHtml(agent.focus)}</p><p class="agent-result">${escapeHtml(result)}</p>${attention.length ? attention.map(findingCard).join("\n") : `<article class="empty"><strong>Result:</strong> ${escapeHtml(result)} The report deliberately does not create a generic remediation task without a concrete signal.</article>`}${controls.length ? `<section class="controls"><strong>Observed controls and limited review notes (${controls.length})</strong><ul>${controls.map((item) => `<li><strong>${escapeHtml(item.title)}:</strong> ${escapeHtml(item.evidence)}</li>`).join("")}</ul></section>` : ""}</section>`;
}

export function createPdfPrintDocument(report: AssessmentReport) {
  const attentionFindings = report.findings.filter((item) => item.status === "attention");
  const completedAgents = report.specialists.filter((item) => item.state === "complete").length;
  const evidence = report.evidenceSummary.ownerEvidenceProvided
    ? `${report.evidenceSummary.sourceFilesReviewed} redacted owner file(s) were reviewed for this report only. Evidence contents are never included in this PDF.`
    : "No owner evidence was supplied; owner-evidence agents remain limited.";
  const groups = chunk(report.specialists, 3);
  const agentPages = groups.map((group, index) => `<section class="pdf-page agent-page"><header><div class="tag">WEBSCAN · DETAILED AGENT READOUT · ${group.map((agent) => agent.id.toUpperCase()).join(" / ")}</div><h2>Agent findings & remediation</h2><p>Each agent reports only what its available evidence supports. Attention findings contain a specific required change and an acceptance check; no generic remediation is invented.</p></header>${group.map((agent, offset) => agentReadout(agent, index * 3 + offset, report.findings)).join("\n")}<p class="page-number">WebScan PDF report · Detailed agent readouts · ${index + 1} / ${groups.length}</p></section>`).join("\n");
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>WebScan PDF — ${escapeHtml(report.hostname)}</title><style>@page{size:A4;margin:12mm}*{box-sizing:border-box}body{margin:0;background:#f3f0e7;color:#24231f;font:10.3pt/1.5 "DM Mono",ui-monospace,monospace}.pdf-page{min-height:273mm;break-after:page;page-break-after:always}.pdf-page:last-child{break-after:auto;page-break-after:auto}header{border-top:4px solid #2687d7;border-bottom:1px solid #24231f;padding:14px 0 18px}h1,h2,h3{font-family:"DM Sans",Arial,sans-serif;letter-spacing:-.04em}h1{font-size:31pt;line-height:1;margin:9px 0}h2{font-size:18pt;margin:0 0 14px}h3{font-size:14pt;margin:6px 0}.tag,.agent-index{font-size:8pt;color:#1e628e;letter-spacing:.12em;font-weight:700}.summary{display:grid;grid-template-columns:repeat(4,1fr);margin-top:18px;border:1px solid #24231f;background:#fbf9f2}.summary div{padding:10px;border-right:1px solid #24231f}.summary div:last-child{border:0}.summary span,dt{display:block;font-size:7.5pt;letter-spacing:.09em;color:#246c61}.summary b{display:block;font:600 20pt "DM Sans",Arial,sans-serif;margin-top:4px}.notice{background:#e8e2d2;border-left:3px solid #2f9b78;padding:11px 13px;margin:18px 0}.columns{display:grid;grid-template-columns:1fr 1fr;gap:22px}.columns ul{padding-left:17px;margin:7px 0}.columns li{margin:6px 0}.agent{border:1px solid #24231f;background:#fffdf7;padding:14px;margin:15px 0;break-inside:avoid}.agent-heading{display:flex;align-items:start;justify-content:space-between;gap:12px}.agent-state{text-align:right;font-size:8pt;letter-spacing:.08em;color:#246c61;font-weight:700}.agent-focus,.agent-result{margin:8px 0}.agent-result{background:#edf4ef;border-left:3px solid #2f9b78;padding:8px 10px}.finding,.empty{background:#fbf9f2;border:1px solid #24231f;border-top:3px solid #e7b742;box-shadow:3px 3px 0 rgba(36,35,31,.15);padding:12px;margin:11px 0;break-inside:avoid}.finding-meta{display:flex;justify-content:space-between;gap:12px;font-size:8pt}.finding-meta b{color:#725516}.finding-meta span,small{color:#64645c}dl{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;border-top:1px solid #aaa59a;padding-top:9px}dd{margin:3px 0 0}.controls{font-size:9pt;background:#f0eee7;padding:8px 10px}.controls ul{margin:7px 0 0;padding-left:18px}.controls li{margin:5px 0}pre{white-space:pre-wrap;background:#1c1d1a;color:#d3f2e9;padding:16px;border-top:4px solid #2f9b78;overflow-wrap:anywhere;font:9pt/1.48 "DM Mono",ui-monospace,monospace}.page-number{color:#64645c;font-size:8pt;margin-top:14px}@media print{body{background:#fff}.finding{box-shadow:none}}</style></head><body><section class="pdf-page"><header><div class="tag">WEBSCAN · PDF SECURITY REPORT · SCORE & SCOPE</div><h1>${escapeHtml(report.hostname)}</h1><p>Verified review completed ${escapeHtml(report.verifiedAt)}. This PDF contains bounded, evidence-based findings only.</p><div class="summary"><div><span>POSTURE SCORE</span><b>${report.score}/100</b></div><div><span>GRADE</span><b>${escapeHtml(report.grade)}</b></div><div><span>ATTENTION</span><b>${attentionFindings.length}</b></div><div><span>AGENTS</span><b>${completedAgents}/15</b></div></div></header><section class="notice"><strong>Scope note.</strong> ${escapeHtml(reportPreamble(report))}</section><div class="columns"><section><h2>Owner evidence</h2><p>${escapeHtml(evidence)}</p><h2>Coverage</h2><ul>${report.coverage.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul></section><section><h2>Limitations</h2><ul>${report.limitations.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul><h2>How to read the detailed report</h2><p>Every agent appears in the following pages. A completed agent without an attention item is not proof that its area is vulnerability-free; it simply did not receive a concrete signal in the reviewed material.</p></section></div><p class="page-number">WebScan PDF report · Score & scope</p></section>${agentPages}<section class="pdf-page"><header><div class="tag">WEBSCAN · CONSOLIDATED REMEDIATION PROMPT · FINAL PAGE</div><h2>Remediation prompt</h2><p>This consolidated implementation brief contains the agent evidence and corrective work documented in the previous pages. It preserves the report's defensive limits.</p></header><pre>${escapeHtml(report.generatedPrompt)}</pre><section class="notice"><strong>Safety constraints retained.</strong> The implementation must not add tracking, weaken authentication, hardcode secrets, expose private data in logs, or include exploit payloads, attack automation, or bypass instructions.</section><p class="page-number">WebScan PDF report · Consolidated remediation prompt</p></section></body></html>`;
}

export function openPdfExport(report: AssessmentReport) {
  const printWindow = window.open("", "_blank", "popup");
  if (!printWindow) return false;
  printWindow.opener = null;
  printWindow.document.open();
  printWindow.document.write(createPdfPrintDocument(report));
  printWindow.document.close();
  printWindow.focus();
  window.setTimeout(() => printWindow.print(), 180);
  return true;
}
