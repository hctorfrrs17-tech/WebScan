export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type FindingStatus = "attention" | "pass" | "observe";

export type Finding = {
  id: string;
  specialist: string;
  title: string;
  severity: Severity;
  status: FindingStatus;
  confidence: "high" | "medium" | "low";
  evidence: string;
  impact: string;
  remediation: string;
  verification: string;
  reference?: string;
};

export type SpecialistSummary = {
  id: string;
  label: string;
  focus: string;
  state: "complete" | "limited" | "not-run";
  findingCount: number;
};

export type OwnerEvidenceFile = {
  name: string;
  content: string;
};

export type EvidenceSummary = {
  ownerEvidenceProvided: boolean;
  sourceFilesReviewed: number;
  reviewedFileTypes: string[];
  handling: "current-review-only";
};

export type AssessmentReport = {
  id: string;
  target: string;
  hostname: string;
  verifiedAt: string;
  score: number;
  grade: "A" | "B" | "C" | "D" | "E";
  coverage: string[];
  limitations: string[];
  specialists: SpecialistSummary[];
  evidenceSummary: EvidenceSummary;
  findings: Finding[];
  generatedPrompt: string;
};

export type VerificationChallenge = {
  id: string;
  target: string;
  hostname: string;
  token: string;
  challengePath: string;
  instructions: string;
};
