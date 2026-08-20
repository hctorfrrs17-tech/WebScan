import { describe, expect, it } from "vitest";
import { buildOwnerEvidenceFindings, specialistSummaries } from "./assessment.js";
import { validateOwnerEvidence } from "./ownerEvidence.js";

describe("owner-provided evidence safeguards", () => {
  it("accepts small redacted evidence without creating generic findings", () => {
    const evidence = validateOwnerEvidence([
      { name: "src/auth.ts", content: "export const login = () => validateInput();" },
      { name: "package.json", content: '{"scripts":{"test":"vitest"}}' },
      { name: ".env.example", content: "API_KEY=your_api_key_here" }
    ]);
    expect(evidence).toHaveLength(3);
    expect(buildOwnerEvidenceFindings(evidence)).toHaveLength(0);
  });

  it("creates one actionable finding for a concrete unsafe rendering signal", () => {
    const evidence = validateOwnerEvidence([{ name: "src/view.tsx", content: "return <div dangerouslySetInnerHTML={{ __html: userHtml }} />;" }]);
    const findings = buildOwnerEvidenceFindings(evidence);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ specialist: "Input safety agent", severity: "high", status: "attention" });
    expect(findings[0].remediation).toContain("sanitize");
    expect(findings[0].verification).toContain("script tags");
  });

  it("rejects real environment files and likely live credentials", () => {
    expect(() => validateOwnerEvidence([{ name: ".env", content: "API_KEY=redacted" }])).toThrow("real .env");
    expect(() => validateOwnerEvidence([{ name: "config.ts", content: "const token = 'ghp_abcdefghijklmnopqrstuvwx';" }])).toThrow("live secret");
    expect(() => validateOwnerEvidence([{ name: "keys.txt", content: "-----BEGIN PRIVATE KEY-----" }])).toThrow("live secret");
  });

  it("always exposes a 15-agent catalog even when owner evidence is unavailable", () => {
    expect(specialistSummaries([])).toHaveLength(15);
  });
});
