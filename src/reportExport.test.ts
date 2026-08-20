import { describe, expect, it } from "vitest";
import { createReportExport, reportToMarkdown, reportToPrintHtml } from "./reportExport";
import type { AssessmentReport } from "../shared/types";

const report: AssessmentReport = {
  id: "abc12345-def0", target: "https://demo.webscan.test", hostname: "demo.webscan.test", verifiedAt: "2026-08-20T12:00:00.000Z", score: 72, grade: "B", coverage: ["Headers"], limitations: ["No exploitation"], specialists: [{ id: "surface", label: "Surface", focus: "Headers", state: "complete", findingCount: 1 }], evidenceSummary: { ownerEvidenceProvided: false, sourceFilesReviewed: 0, reviewedFileTypes: [], handling: "current-review-only" }, generatedPrompt: "Preserve behavior. Do not include exploit payloads.", findings: [{ id: "finding-1", specialist: "Surface", title: "A < CSP", severity: "medium", status: "attention", confidence: "high", evidence: "No cookie=secret is retained.", impact: "Containment is weaker.", remediation: "Add a policy.", verification: "Check headers." }]
};

describe("WebScan report exports", () => {
  it("creates a readable markdown report with the prompt and bounded scope", () => {
    const markdown = reportToMarkdown(report);
    expect(markdown).toContain("# WebScan defensive posture review");
    expect(markdown).toContain("AI coding remediation brief");
    expect(markdown).toContain("does not prove the absence of vulnerabilities");
    expect(markdown).toContain("15-agent readout");
  });

  it("escapes dynamic content in the printable HTML output", () => {
    const html = reportToPrintHtml(report);
    expect(html).toContain("A &lt; CSP");
    expect(html).not.toContain("<h3>A < CSP</h3>");
    expect(html).toContain("15-AGENT DEFENSIVE POSTURE REVIEW");
  });

  it("returns safe filenames and MIME types for every export format", () => {
    expect(createReportExport(report, "json")).toMatchObject({ filename: "webscan-demo.webscan.test-abc12345.json", mimeType: "application/json" });
    expect(createReportExport(report, "markdown")).toMatchObject({ filename: "webscan-demo.webscan.test-abc12345.md", mimeType: "text/markdown;charset=utf-8" });
    expect(createReportExport(report, "html")).toMatchObject({ filename: "webscan-demo.webscan.test-abc12345.html", mimeType: "text/html;charset=utf-8" });
  });
});
