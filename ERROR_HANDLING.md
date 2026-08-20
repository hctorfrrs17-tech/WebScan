# Error handling and recovery

WebScan fails closed. If it cannot verify control of a domain or collect a complete bounded public response, it stops the relevant phase and shows a recovery panel. It does not continue from partial evidence and does not generate a speculative security report.

| Failed phase | What the recovery panel explains | Safe next action |
| --- | --- | --- |
| Target setup | The supplied address is outside the public defensive-review boundary. | Use a public HTTP/HTTPS production hostname that you own or are authorized to review. |
| Domain verification | The `/.well-known/webscan-verification.txt` file is missing, redirects, or does not return the exact one-time token. | Publish the exact token as plain text on the deployed HTTPS site and retry. |
| HTTPS connection | The target could not complete a readable TLS/HTTPS connection. | Check the certificate, certificate chain, TLS configuration, production deployment, and DNS propagation for the exact hostname. |
| DNS resolution | The hostname could not be resolved reliably to a public address. | Check hostname spelling, public DNS records, and propagation after deployment changes. |
| Response timeout | The target did not respond before WebScan’s bounded timeout. | Check production hosting health, origin reachability, and firewall rules, then retry. |
| Redirect | The target redirected and WebScan did not follow it automatically. | Start a fresh review with the final public HTTPS URL shown by the browser. |

> WebScan never requests credentials, follows arbitrary redirects, bypasses authentication, fuzzes inputs, or disables certificate validation to work around one of these errors.
