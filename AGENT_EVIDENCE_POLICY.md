# Evidence threshold for actionable agent findings

WebScan distinguishes between an **agent that has reviewed evidence** and an **actionable finding**. An agent may complete a review without producing a finding. It must not create a vague remediation request solely because a file mentions a broad topic such as login, storage, database, role, or configuration.

## Actionable threshold

An owner-evidence agent creates an `attention` finding only when the selected redacted material contains a concrete, deterministic signal that maps to a specific correction. The signal, impact, required change, and verification step must all be representable without retaining a source excerpt.

| Agent | Concrete evidence required for an actionable finding | Specific remediation outcome |
| --- | --- | --- |
| Authentication | A literal JWT signing value or a weak password-hash primitive | Move the signing value to a secret manager/configuration and use a modern password-hash primitive. |
| Authorization | A role or privilege value accepted directly from a request body | Derive privileges server-side and validate role/ownership at the protected action. |
| Input safety | `eval`, `new Function`, `innerHTML`, or `dangerouslySetInnerHTML` | Remove the unsafe sink or sanitize/encode through an approved boundary. |
| API & error | A stack trace is returned in a response | Replace it with a stable client error while logging safely on the server. |
| Configuration | A wildcard CORS policy or development mode forced as a runtime default | Restrict the origin policy and require an explicit production runtime setting. |
| Dependencies | `latest`, `*`, or early `0.x` ranges in a package manifest | Pin/review dependency versions and commit the lockfile. |
| Supply chain | `pull_request_target`, `curl | sh`, or unpinned privileged installation logic | Reduce workflow permissions and pin/review the installer or action. |
| Deployment | Privileged container, root runtime, or explicit non-root disablement | Run with least privilege and enforce a non-root runtime. |
| Logging & recovery | Logging of a password, token, secret, or recovery artifact | Redact sensitive fields before logging and test the redaction policy. |
| Storage & cryptography | MD5/SHA-1 password hashing or deprecated cipher construction | Replace with a modern password hash or maintained authenticated-encryption API. |

## Prompt rule

The generated coding prompt contains only `attention` findings. Every objective must include the observed signal, the required code/configuration change, and a testable acceptance criterion. It must never instruct a coding assistant to “review” a generic subsystem without a concrete finding.
