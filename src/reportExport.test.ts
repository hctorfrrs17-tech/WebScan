import { describe, expect, it } from "vitest";
import { createPdfPrintDocument } from "./reportExport";
import type { AssessmentReport, SpecialistSummary } from "../shared/types";

const report: AssessmentReport = {
  id: "abc12345-def0", target: "https://demo.webscan.test", hostname: "demo.webscan.test", verifiedAt: "2026-08-20T12:00:00.000Z", score: 72, grade: "B", coverage: ["Headers"], limitations: ["No exploitation"], specialists: [{ id: "surface", label: "Surface", focus: "Headers", state: "complete", findingCount: 1 }], evidenceSummary: { ownerEvidenceProvided: false, sourceFilesReviewed: 0, reviewedFileTypes: [], handling: "current-review-only" }, generatedPrompt: "Preserve behavior. Do not include exploit payloads.", findings: [{ id: "finding-1", specialist: "Surface", title: "A < CSP", severity: "medium", status: "attention", confidence: "high", evidence: "No cookie=secret is retained.", impact: "Containment is weaker.", remediation: "Add a policy.", verification: "Check headers." }]
};

describe("WebScan PDF export", () => {
  it("creates a safe detailed print document with score, agent, and prompt pages", () => {
    const html = createPdfPrintDocument(report);
    expect(html).toContain("SCORE & SCOPE");
    expect(html).toContain("DETAILED AGENT READOUT");
    expect(html).toContain("AGENT 01");
    expect(html).toContain("Remediation prompt");
    expect(html).toContain("page-break-after:always");
  });

  it("escapes dynamic content and includes exact remediation fields", () => {
    const html = createPdfPrintDocument(report);
    expect(html).toContain("A &lt; CSP");
    expect(html).not.toContain("<h3>A < CSP</h3>");
    expect(html).toContain("Required change");
    expect(html).toContain("Acceptance check");
  });

  it("redacts sensitive dynamic evidence and keeps an agent readout when no attention finding exists", () => {
    const html = createPdfPrintDocument({ ...report, findings: [] });
    expect(html).toContain("No evidence-backed attention finding was produced by this agent");
    expect(html).toContain("Consolidated remediation prompt");
    expect(createPdfPrintDocument(report)).not.toContain("cookie=secret");
    expect(createPdfPrintDocument(report)).toContain("cookie=[redacted]");
  });

  it("gives all fifteen supplied agents an attributed report section and preserves the full prompt", () => {
    const labels = ["Transport agent", "Browser isolation agent", "Session agent", "Authentication agent", "Authorization agent", "Input safety agent", "Client exposure agent", "API & error agent", "Data privacy agent", "Configuration hygiene agent", "Dependency agent", "Supply-chain agent", "Deployment agent", "Logging & recovery agent", "Storage & cryptography agent"];
    const specialists: SpecialistSummary[] = labels.map((label, index) => ({ id: `agent-${index + 1}`, label, focus: `Scope ${index + 1}`, state: "complete", findingCount: 0 }));
    const html = createPdfPrintDocument({ ...report, specialists, findings: [], generatedPrompt: "Complete consolidated remediation prompt." });
    labels.forEach((label) => expect(html).toContain(label.replace("&", "&amp;")));
    expect(html).toContain("AGENT 15");
    expect(html).toContain("Complete consolidated remediation prompt.");
  });
});
