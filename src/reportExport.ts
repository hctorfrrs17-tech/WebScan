import type { AssessmentReport } from "../shared/types";

export type ExportFormat = "json" | "markdown" | "html";

type ExportArtifact = { content: string; filename: string; mimeType: string };

function safeFilenamePart(value: string) {
  return value.replace(/[^a-z0-9.-]+/gi, "-").replace(/^-+|-+$/g, "").toLowerCase() || "report";
}

function escapeHtml(value: string) {
  return value.replace(/[&<>'"]/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", "\"": "&quot;" })[character] ?? character);
}

function escapeMarkdown(value: string) {
  return value.replace(/([\\`*_{}\[\]<>])/g, "\\$1");
}

function reportPreamble(report: AssessmentReport) {
  return `This is a bounded defensive posture review for ${report.target}. It does not prove the absence of vulnerabilities and does not contain raw cookie values or private credentials.`;
}

export function reportToMarkdown(report: AssessmentReport) {
  const attention = report.findings.filter((item) => item.status === "attention").length;
  const findings = report.findings.map((item) => `### ${escapeMarkdown(item.title)}\n\n- **Lens:** ${escapeMarkdown(item.specialist)}\n- **Severity:** ${item.severity}\n- **Status:** ${item.status}\n- **Confidence:** ${item.confidence}\n- **Observed:** ${escapeMarkdown(item.evidence)}\n- **Why it matters:** ${escapeMarkdown(item.impact)}\n- **Remediation:** ${escapeMarkdown(item.remediation)}\n- **Verify:** ${escapeMarkdown(item.verification)}${item.reference ? `\n- **Reference:** ${escapeMarkdown(item.reference)}` : ""}`).join("\n\n");
  return `# WebScan defensive posture review\n\n> ${reportPreamble(report)}\n\n| Target | Score | Grade | Attention items | Reviewed at |\n| --- | ---: | --- | ---: | --- |\n| ${escapeMarkdown(report.target)} | ${report.score}/100 | ${report.grade} | ${attention} | ${report.verifiedAt} |\n\n## Coverage\n\n${report.coverage.map((item) => `- ${escapeMarkdown(item)}`).join("\n")}\n\n## Limitations\n\n${report.limitations.map((item) => `- ${escapeMarkdown(item)}`).join("\n")}\n\n## Findings\n\n${findings}\n\n## AI coding remediation brief\n\n\`\`\`text\n${report.generatedPrompt}\n\`\`\`\n`;
}

export function reportToPrintHtml(report: AssessmentReport) {
  const attention = report.findings.filter((item) => item.status === "attention").length;
  const findings = report.findings.map((item) => `<article class="finding"><div class="finding-meta"><b>${escapeHtml(item.severity.toUpperCase())}</b><span>${escapeHtml(item.specialist)} · ${escapeHtml(item.confidence)} confidence</span></div><h3>${escapeHtml(item.title)}</h3><p><strong>Observed:</strong> ${escapeHtml(item.evidence)}</p><dl><div><dt>Why it matters</dt><dd>${escapeHtml(item.impact)}</dd></div><div><dt>Remediation</dt><dd>${escapeHtml(item.remediation)}</dd></div><div><dt>Verify</dt><dd>${escapeHtml(item.verification)}</dd></div></dl>${item.reference ? `<small>${escapeHtml(item.reference)}</small>` : ""}</article>`).join("\n");
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>WebScan — ${escapeHtml(report.hostname)}</title><style>body{margin:0;background:#f3f0e7;color:#24231f;font:14px/1.55 "DM Mono",ui-monospace,monospace}.page{max-width:960px;margin:0 auto;padding:42px}header{border-top:4px solid #2687d7;border-bottom:1px solid #24231f;padding:18px 0 24px}h1,h2,h3{font-family:"DM Sans",Arial,sans-serif;letter-spacing:-.04em}h1{font-size:42px;margin:10px 0}h2{font-size:22px;margin:34px 0 12px}h3{font-size:19px;margin:12px 0}.tag{font-size:11px;color:#1e628e;letter-spacing:.12em;font-weight:700}.summary{display:grid;grid-template-columns:repeat(4,1fr);margin-top:20px;border:1px solid #24231f;background:#fbf9f2}.summary div{padding:12px;border-right:1px solid #24231f}.summary div:last-child{border:0}.summary b{display:block;font:600 23px "DM Sans",Arial,sans-serif}.notice{background:#e8e2d2;border-left:3px solid #2f9b78;padding:13px 15px;margin:22px 0}.finding{background:#fbf9f2;border:1px solid #24231f;border-top:3px solid #e7b742;box-shadow:3px 3px 0 rgba(36,35,31,.15);padding:18px;margin:15px 0;break-inside:avoid}.finding-meta{display:flex;justify-content:space-between;font-size:11px}.finding-meta b{color:#725516}.finding-meta span,small{color:#64645c}dl{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;border-top:1px solid #aaa59a;padding-top:13px}dt{font-size:10px;text-transform:uppercase;letter-spacing:.09em;color:#246c61}dd{margin:4px 0 0}pre{white-space:pre-wrap;background:#1c1d1a;color:#bdebdc;padding:18px;border-top:4px solid #2f9b78;overflow-wrap:anywhere}@media print{body{background:#fff}.page{max-width:none;padding:20px}.finding{box-shadow:none}.summary{break-inside:avoid}}@media(max-width:650px){.summary,dl{grid-template-columns:1fr}.summary div{border-right:0;border-bottom:1px solid #24231f}.summary div:last-child{border-bottom:0}}</style></head><body><main class="page"><header><div class="tag">WEBSCAN · DEFENSIVE POSTURE REVIEW</div><h1>${escapeHtml(report.hostname)}</h1><p>Reviewed ${escapeHtml(report.verifiedAt)}. This export contains bounded, evidence-based findings only.</p><div class="summary"><div><span>POSTURE SCORE</span><b>${report.score}/100</b></div><div><span>GRADE</span><b>${escapeHtml(report.grade)}</b></div><div><span>ATTENTION</span><b>${attention}</b></div><div><span>COVERAGE</span><b>${report.specialists.filter((item) => item.state === "complete").length}/07</b></div></div></header><section class="notice"><strong>Scope note.</strong> ${escapeHtml(reportPreamble(report))}</section><section><h2>Coverage</h2><ul>${report.coverage.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul><h2>Limitations</h2><ul>${report.limitations.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul></section><section><h2>Findings</h2>${findings}</section><section><h2>AI coding remediation brief</h2><pre>${escapeHtml(report.generatedPrompt)}</pre></section></main></body></html>`;
}

export function createReportExport(report: AssessmentReport, format: ExportFormat): ExportArtifact {
  const base = `webscan-${safeFilenamePart(report.hostname)}-${report.id.slice(0, 8)}`;
  if (format === "markdown") return { content: reportToMarkdown(report), filename: `${base}.md`, mimeType: "text/markdown;charset=utf-8" };
  if (format === "html") return { content: reportToPrintHtml(report), filename: `${base}.html`, mimeType: "text/html;charset=utf-8" };
  return { content: JSON.stringify({ ...report, exportedAt: new Date().toISOString(), exportNotice: reportPreamble(report) }, null, 2), filename: `${base}.json`, mimeType: "application/json" };
}
