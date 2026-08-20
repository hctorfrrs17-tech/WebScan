import type { RecoveryIssue, ReviewPhase } from "../shared/types.js";

const phaseLabel: Record<ReviewPhase, string> = {
  challenge: "target setup",
  verification: "domain verification",
  analysis: "15-agent review"
};

function issue(phase: ReviewPhase, code: RecoveryIssue["code"], title: string, detail: string, steps: string[]): RecoveryIssue {
  return { phase, code, title, detail, steps };
}

export function verificationFileIssue(): RecoveryIssue {
  return issue(
    "verification",
    "verification-file",
    "WebScan could not confirm domain control yet",
    "The public verification file did not return the exact one-time token generated for this review.",
    [
      "Publish /.well-known/webscan-verification.txt on the production site, not only in a local preview.",
      "Return only the displayed token: no HTML, JSON, quotes, redirects, or extra whitespace.",
      "Open the HTTPS verification URL in a private browser window, then retry verification."
    ]
  );
}

export function redirectIssue(): RecoveryIssue {
  return issue(
    "analysis",
    "redirect",
    "The target redirected before WebScan could review it",
    "WebScan keeps the review bounded and does not follow redirects automatically.",
    [
      "Open the target URL in a browser and copy the final HTTPS address after any redirect.",
      "Start a new review using that final public HTTPS address.",
      "Keep the verification file available on the same final public domain."
    ]
  );
}

export function classifyReviewError(phase: ReviewPhase, error: unknown): RecoveryIssue {
  const source = error instanceof Error ? `${error.name} ${error.message}`.toLowerCase() : "";

  if (/certificate|ssl|tls|secure connection|wrong version|fetch failed/.test(source)) {
    return issue(
      phase,
      "https",
      "WebScan could not establish a secure HTTPS connection",
      `The ${phaseLabel[phase]} stopped before evidence could be collected because the target did not complete a readable HTTPS connection from WebScan.`,
      [
        "Open the public HTTPS URL from a private browser window and confirm it loads without a certificate or protocol warning.",
        "Confirm the production deployment has a valid certificate, a complete certificate chain, and TLS enabled for the exact hostname.",
        "If the site was just published, wait for deployment and certificate propagation, then retry the same review."
      ]
    );
  }

  if (/abort|timeout|timed out/.test(source)) {
    return issue(
      phase,
      "timeout",
      "The target did not respond within WebScan's safe time limit",
      `The ${phaseLabel[phase]} stopped after the bounded response timeout, so WebScan did not continue with incomplete evidence.`,
      [
        "Open the public target URL and confirm it responds promptly without a long loading screen or gateway error.",
        "Check the production hosting, origin health, and firewall rules for the exact public hostname.",
        "Retry after the site is reachable; WebScan will create a fresh bounded request."
      ]
    );
  }

  if (/enotfound|getaddrinfo|eai_again|dns|resolve/.test(source)) {
    return issue(
      phase,
      "dns",
      "WebScan could not resolve the public domain",
      `The ${phaseLabel[phase]} stopped before connecting because the hostname could not be resolved reliably to a public address.`,
      [
        "Check the spelling of the public hostname and confirm its DNS record is active.",
        "Use the deployed production URL rather than a local, preview-only, or private-network address.",
        "Wait for DNS propagation after a recent domain or deployment change, then retry."
      ]
    );
  }

  if (/private network|local, metadata|public internet|standard web ports|credentials are not permitted/.test(source)) {
    return issue(
      phase,
      "target-input",
      "The target is outside WebScan's defensive review boundary",
      error instanceof Error ? error.message : "The supplied target cannot be reviewed safely.",
      [
        "Use a public HTTP or HTTPS production hostname that you own or are authorized to assess.",
        "Do not use localhost, intranet addresses, private IP ranges, URL credentials, or non-standard ports.",
        "Create a new challenge after correcting the target URL."
      ]
    );
  }

  return issue(
    phase,
    "unreachable",
    "WebScan could not complete this phase",
    `The ${phaseLabel[phase]} stopped before a complete evidence-backed result was available.`,
    [
      "Confirm the public target is online and reachable over HTTPS.",
      "Confirm the selected URL is the deployed production address, not a local preview.",
      "Retry the phase after correcting the target-side issue; WebScan will not fabricate a report."
    ]
  );
}
