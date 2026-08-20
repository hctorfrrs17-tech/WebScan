import type { EvidenceSummary, OwnerEvidenceFile } from "../shared/types.js";

const MAX_FILES = 8;
const MAX_FILE_BYTES = 12_000;
const MAX_TOTAL_BYTES = 48_000;
const allowedExtensions = new Set([".ts", ".tsx", ".js", ".jsx", ".json", ".yml", ".yaml", ".toml", ".md", ".txt", ".env.example"]);

const highRiskSecretPatterns = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/i,
  /\b(?:ghp|gho|ghu|ghs|github_pat)_[A-Za-z0-9_]{20,}/,
  /\bAKIA[0-9A-Z]{16}\b/,
  /\bsk_(?:live|test)_[A-Za-z0-9]{16,}/,
  /\b(?:xox[baprs]-)[A-Za-z0-9-]{20,}/,
  /\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/
];

function extensionFor(name: string) {
  const lowered = name.toLowerCase();
  if (lowered.endsWith(".env.example")) return ".env.example";
  const index = lowered.lastIndexOf(".");
  return index >= 0 ? lowered.slice(index) : "";
}

function looksLikeAssignedSecret(content: string) {
  const assigned = /(?:password|secret|token|api[_-]?key|private[_-]?key)\s*[:=]\s*["']([^"'\n]{12,})["']/i.exec(content);
  if (!assigned) return false;
  return !/^(example|placeholder|replace[-_ ]?me|your[-_ ]?(?:key|token|secret|password)|changeme|dummy)/i.test(assigned[1]);
}

export function validateOwnerEvidence(value: unknown): OwnerEvidenceFile[] {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) throw new Error("Owner evidence must be a list of redacted text files.");
  if (value.length > MAX_FILES) throw new Error(`Provide at most ${MAX_FILES} redacted evidence files per review.`);

  let totalBytes = 0;
  return value.map((entry, index) => {
    if (!entry || typeof entry !== "object" || typeof (entry as OwnerEvidenceFile).name !== "string" || typeof (entry as OwnerEvidenceFile).content !== "string") {
      throw new Error(`Evidence item ${index + 1} is not a valid text file.`);
    }
    const file = entry as OwnerEvidenceFile;
    const name = file.name.trim().replace(/[^A-Za-z0-9._/-]/g, "-").slice(0, 120);
    if (/^\.env(?:$|\.)/i.test(name) && !/\.env\.example$/i.test(name)) throw new Error("Do not upload a real .env file. Use a redacted .env.example instead.");
    if (!name || name.includes("..") || !allowedExtensions.has(extensionFor(name))) throw new Error("Evidence files must be redacted source, configuration, manifest, workflow, or text files.");
    const bytes = Buffer.byteLength(file.content, "utf8");
    if (!bytes || bytes > MAX_FILE_BYTES) throw new Error(`Each evidence file must be a non-empty text file under ${MAX_FILE_BYTES} bytes.`);
    totalBytes += bytes;
    if (totalBytes > MAX_TOTAL_BYTES) throw new Error(`The combined evidence bundle must stay under ${MAX_TOTAL_BYTES} bytes.`);
    if (highRiskSecretPatterns.some((pattern) => pattern.test(file.content)) || looksLikeAssignedSecret(file.content)) {
      throw new Error("Evidence appears to contain a live secret or credential. Remove it and submit a redacted placeholder instead.");
    }
    return { name, content: file.content };
  });
}

export function summarizeOwnerEvidence(files: OwnerEvidenceFile[]): EvidenceSummary {
  const reviewedFileTypes = [...new Set(files.map((file) => extensionFor(file.name) || "text"))].sort();
  return { ownerEvidenceProvided: files.length > 0, sourceFilesReviewed: files.length, reviewedFileTypes, handling: "current-review-only" };
}
