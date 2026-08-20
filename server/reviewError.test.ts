import { describe, expect, it } from "vitest";
import { classifyReviewError, redirectIssue, verificationFileIssue } from "./reviewError.js";

describe("review recovery guidance", () => {
  it("turns transport failures into HTTPS recovery guidance", () => {
    const issue = classifyReviewError("verification", new Error("fetch failed: ERR_SSL_PROTOCOL_ERROR"));
    expect(issue).toMatchObject({ phase: "verification", code: "https", title: "WebScan could not establish a secure HTTPS connection" });
    expect(issue.steps.join(" ")).toContain("certificate");
  });

  it("explains token mismatches without exposing a token", () => {
    const issue = verificationFileIssue();
    expect(issue).toMatchObject({ phase: "verification", code: "verification-file" });
    expect(issue.detail).not.toContain("token-value");
    expect(issue.steps.join(" ")).toContain("extra whitespace");
  });

  it("explains bounded redirect handling", () => {
    const issue = redirectIssue();
    expect(issue).toMatchObject({ phase: "analysis", code: "redirect" });
    expect(issue.steps.join(" ")).toContain("final HTTPS address");
  });
});
