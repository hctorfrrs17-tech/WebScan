import express from "express";
import { randomBytes, randomUUID } from "node:crypto";
import { createReport, fetchSafely, parsePublicTarget, type TargetRecord } from "./assessment.js";
import { validateOwnerEvidence } from "./ownerEvidence.js";
import { classifyReviewError, redirectIssue, verificationFileIssue } from "./reviewError.js";

const app = express();
const port = Number(process.env.PORT ?? 8787);
const records = new Map<string, TargetRecord>();

app.use(express.json({ limit: "96kb" }));
app.use((_, response, next) => {
  response.setHeader("Cache-Control", "no-store");
  response.setHeader("X-Content-Type-Options", "nosniff");
  next();
});

app.post("/api/challenges", async (request, response) => {
  try {
    const { target, authorizationConfirmed, ownerEvidence } = request.body as { target?: string; authorizationConfirmed?: boolean; ownerEvidence?: unknown };
    if (!authorizationConfirmed) return response.status(400).json({ error: "Confirm that you own the target or have written authorization before continuing." });
    const parsed = parsePublicTarget(target ?? "");
    const id = randomUUID();
    const token = randomBytes(18).toString("base64url");
    const challenge = {
      id,
      target: parsed.toString(),
      hostname: parsed.hostname,
      token,
      challengePath: "/.well-known/webscan-verification.txt",
      instructions: `Create https://${parsed.hostname}/.well-known/webscan-verification.txt containing exactly this token.`
    };
    const evidence = validateOwnerEvidence(ownerEvidence);
    records.set(id, { challenge, ownerEvidence: evidence });
    response.status(201).json({ ...challenge, ownerEvidenceAccepted: evidence.length, evidenceHandling: "current-review-only" });
  } catch (error) {
    const issue = classifyReviewError("challenge", error);
    response.status(400).json({ error: issue.detail, issue });
  }
});

app.post("/api/challenges/:id/verify", async (request, response) => {
  const record = records.get(request.params.id);
  if (!record) return response.status(404).json({ error: "Verification challenge not found. Start again to generate a new challenge." });
  try {
    const verificationUrl = new URL(record.challenge.challengePath, record.challenge.target);
    const verificationResponse = await fetchSafely(verificationUrl);
    if (verificationResponse.status < 200 || verificationResponse.status >= 300 || verificationResponse.html.trim() !== record.challenge.token) {
      const issue = verificationFileIssue();
      return response.status(422).json({ error: issue.detail, issue });
    }
    record.verifiedAt = new Date().toISOString();
    response.json({ verifiedAt: record.verifiedAt, hostname: record.challenge.hostname });
  } catch (error) {
    const issue = classifyReviewError("verification", error);
    response.status(422).json({ error: issue.detail, issue });
  }
});

app.post("/api/challenges/:id/analyze", async (request, response) => {
  const record = records.get(request.params.id);
  if (!record) return response.status(404).json({ error: "Assessment not found. Start a new authorized assessment." });
  if (!record.verifiedAt) return response.status(403).json({ error: "Verify domain control before starting the defensive review." });
  try {
    const target = parsePublicTarget(record.challenge.target);
    const safeResponse = await fetchSafely(target);
    if (safeResponse.status >= 300 && safeResponse.status < 400) {
      const issue = redirectIssue();
      return response.status(422).json({ error: issue.detail, issue });
    }
    response.json(createReport(record, safeResponse));
  } catch (error) {
    const issue = classifyReviewError("analysis", error);
    response.status(422).json({ error: issue.detail, issue });
  }
});

app.listen(port, () => console.log(`WebScan API listening on ${port}`));
