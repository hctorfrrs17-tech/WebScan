import { describe, expect, it } from "vitest";
import { buildFindings, buildRemediationPrompt, isPrivateAddress, isReadableResponseType, parsePublicTarget } from "./assessment.js";

describe("WebScan defensive assessment boundaries", () => {
  it("accepts ordinary public web URLs and normalizes their path", () => {
    expect(parsePublicTarget("https://example.com/app").hostname).toBe("example.com");
  });

  it("rejects unsafe target protocols, credentials, local hosts, and non-standard ports", () => {
    expect(() => parsePublicTarget("file:///etc/passwd")).toThrow("Only HTTP and HTTPS");
    expect(() => parsePublicTarget("https://user:pass@example.com")).toThrow("Credentials");
    expect(() => parsePublicTarget("http://localhost:3000")).toThrow("Local");
    expect(() => parsePublicTarget("http://127.0.0.1")).toThrow("Private network");
    expect(() => parsePublicTarget("https://example.com:8080")).toThrow("standard web ports");
  });

  it("recognizes private and metadata-style network destinations", () => {
    expect(isPrivateAddress("10.0.0.2")).toBe(true);
    expect(isPrivateAddress("172.16.0.1")).toBe(true);
    expect(isPrivateAddress("192.168.1.20")).toBe(true);
    expect(isPrivateAddress("169.254.169.254")).toBe(true);
    expect(isPrivateAddress("8.8.8.8")).toBe(false);
  });

  it("reads HTML and plain-text verification responses but not binary content", () => {
    expect(isReadableResponseType("text/html; charset=utf-8")).toBe(true);
    expect(isReadableResponseType("text/plain; charset=utf-8")).toBe(true);
    expect(isReadableResponseType("application/octet-stream")).toBe(false);
  });

  it("creates evidence-based attention items without retaining cookie values", () => {
    const findings = buildFindings({
      url: "https://example.com",
      status: 200,
      headers: new Headers({ "set-cookie": "session=private-value; Path=/" }),
      html: '<script src="http://assets.example.test/app.js"></script>'
    });

    expect(findings.find((item) => item.title === "Content Security Policy")?.status).toBe("attention");
    expect(findings.find((item) => item.title === "Observed cookie hardening is incomplete")?.evidence).not.toContain("private-value");
    expect(findings.find((item) => item.title === "Potential HTTP resource reference")?.status).toBe("attention");
  });

  it("recognizes additional concrete public-response signals without using active attack techniques", () => {
    const findings = buildFindings({
      url: "https://example.com",
      status: 200,
      headers: new Headers(),
      html: '<form action="http://example.com/sign-in"></form><script>localStorage.setItem("token", value)</script>'
    });
    expect(findings.find((item) => item.title === "Framing control is not observed")?.status).toBe("attention");
    expect(findings.find((item) => item.title === "HTML form posts to an HTTP action")?.status).toBe("attention");
    expect(findings.find((item) => item.title === "Security token stored through browser storage API")?.status).toBe("attention");
  });

  it("requires safe constraints in every coding-assistant remediation prompt", () => {
    const prompt = buildRemediationPrompt({
      target: "https://example.com",
      coverage: ["Headers"],
      limitations: ["No exploitation"],
      findings: [{ id: "1", specialist: "Surface", title: "Content Security Policy", severity: "medium", status: "attention", confidence: "high", evidence: "Missing", impact: "Containment", remediation: "Add a restrictive policy", verification: "Check response" }]
    });

    expect(prompt).toContain("Do not include exploit payloads");
    expect(prompt).toContain("Add or update automated tests");
    expect(prompt).toContain("Preserve existing product behavior");
    expect(prompt).toContain("Observed signal: Missing");
    expect(prompt).toContain("Required change: Add a restrictive policy");
    expect(prompt).toContain("Acceptance check: Check response");
  });
});
