# PDF-only report export

WebScan exports reports through the browser’s native print dialog. The application opens a self-contained, print-styled report and immediately requests printing; the user selects **Save to PDF** in the dialog. No JSON, Markdown, or HTML download is offered in the product interface.

## Required pagination and agent attribution

Every report has at least three print pages, even when there are no attention findings. Detailed reports normally contain additional pages because each of the 15 agents receives an attributed readout.

| PDF page | Required content |
| --- | --- |
| **1 — Score & scope** | Target, posture score, grade, coverage, owner-evidence summary, and limitations. |
| **2+ — Agent readouts** | Every agent is named and receives its own evidence scope, completion state, result, and any concrete attention findings. Each finding contains observed signal, impact, exact required change, acceptance check, confidence, and reference. Agents with no concrete issue explicitly state that they did not produce an evidence-backed finding rather than inventing a generic task. |
| **Final — Remediation prompt** | The complete implementation prompt consolidates only the evidence-backed required changes, grouped by agent priority, plus its safety constraints. |

The report uses explicit print page breaks before the agent-readout and prompt sections. It groups three agents per intended readout page, but an agent is never artificially truncated: further concrete findings flow onto additional pages and the final prompt always starts on a fresh page.

## Evidence rules

An agent can report an **attention finding** only when a public response or a current-review redacted owner-evidence file provides a concrete matching signal. The agent must then state the signal and a specific corrective change that can be validated. When the available evidence is insufficient, its result is recorded as **limited** or **no evidence-backed attention finding**, not as a speculative vulnerability.

## Safety properties

The PDF keeps WebScan’s existing safety boundary. It includes evidence summaries and findings, but never raw cookie values, owner-evidence contents, passwords, API keys, tokens, or private keys.
