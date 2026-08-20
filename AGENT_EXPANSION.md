# Expanded defensive evidence model

This expansion increases the **breadth of observable evidence**, not the aggressiveness of WebScan. A check can produce an attention finding only when the verified public response or owner-selected redacted evidence contains its concrete signal. It never sends exploit payloads, guesses credentials, fuzzes inputs, enumerates arbitrary paths, or attempts an authorization bypass.

| Agent | Additional concrete signals to evaluate | Evidence boundary |
| --- | --- | --- |
| Transport | HTTP transport, HSTS, insecure redirects, and TLS-validation bypass configuration | Verified response and redacted deployment/configuration files |
| Browser isolation | CSP, framing control, MIME protection, permissions policy, cross-origin isolation headers, and insecure form submission targets | Verified headers and sampled HTML |
| Session | Cookie flags, cookie path/domain breadth, token lifetime configuration, and session-rotation cues | Visible cookie metadata and owner-selected auth evidence |
| Authentication | Literal signing material, disabled password controls, unsafe reset handling, and authentication cookie configuration | Redacted source/configuration only |
| Authorization | Client-supplied role/tenant/object identifiers trusted at protected actions and missing server-side ownership cues | Redacted server-side routes and policy code only |
| Input safety | Dynamic HTML/JavaScript execution, unsafe template interpolation, permissive upload type handling, and server-side command or query construction cues | Redacted source and sampled HTML |
| Client exposure | HTTP resources, technology banners, source maps, debug artifacts, and direct sensitive browser-storage use | Verified headers/HTML and redacted client code |
| API & error | Client-visible stack traces, verbose error configuration, missing response security defaults, and unsafe redirect handling cues | Public response and redacted server code |
| Data privacy | Referrer policy, cache-control on sensitive routes when supplied, private-data logging cues, and cross-origin data exposure configuration | Verified headers and redacted data-flow/configuration evidence |
| Configuration hygiene | Wildcard CORS, disabled TLS validation, development/debug defaults, unsafe origin allowlists, and placeholder/secret misuse | Redacted configuration templates only |
| Dependency | Wildcard/latest ranges, absent lockfiles, lifecycle scripts, deprecated lockfile metadata, and known package-manager integrity omissions | Owner-selected manifests and lockfiles only |
| Supply chain | Privileged pull-request workflows, unpinned third-party actions, remote installer pipes, excessive token permissions, and artifact/provenance gaps | Redacted CI/release workflows only |
| Deployment | Root or privileged containers, missing non-root policy, unsafe capability additions, publicly exposed management/debug configuration, and weak health/readiness handling | Redacted deployment configuration only |
| Logging & recovery | Sensitive logging, disabled audit/error redaction, recovery artifacts in logs, and missing invalidation/expiry cues | Redacted server/recovery configuration only |
| Storage & cryptography | Deprecated password hashes, weak or static encryption IV/key patterns, plaintext sensitive persistence cues, and insecure transport/storage configuration | Redacted source, configuration, and architecture notes only |

Every resulting report item must include an observed signal, a narrowly scoped corrective change, and a testable acceptance check. The design is guided by OWASP ASVS v5.0.0 and the OWASP WSTG, which describe security control verification and test-scenario frameworks rather than authorization to test arbitrary targets.[1][2]

[1]: https://owasp.org/www-project-application-security-verification-standard/ "OWASP Application Security Verification Standard"
[2]: https://owasp.org/www-project-web-security-testing-guide/ "OWASP Web Security Testing Guide"
