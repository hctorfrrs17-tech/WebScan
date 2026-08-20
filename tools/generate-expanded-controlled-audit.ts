import { writeFile } from "node:fs/promises";
import { createReport, type SafeResponse, type TargetRecord } from "../server/assessment";
import { validateOwnerEvidence } from "../server/ownerEvidence";

const ownerEvidence = validateOwnerEvidence([
  { name: "src/auth.ts", content: "const token = jwt.sign(user, 'placeholder'); const authCookie = { httpOnly: false };" },
  { name: "src/routes.ts", content: "db.findUnique(req.params.userId); exec(req.body.command); res.redirect(req.query.next); return <div dangerouslySetInnerHTML={{ __html: userHtml }} />;" },
  { name: "src/client.ts", content: "localStorage.setItem('accessToken', value);" },
  { name: "config.ts", content: "cors({ origin: '*' }); process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0;" },
  { name: "package.json", content: "{\"dependencies\":{\"example\":\"latest\"},\"scripts\":{\"postinstall\":\"node setup.js\"}}" },
  { name: "workflow.yml", content: "on: pull_request_target\npermissions: write-all\nrun: curl https://installer.example.test | bash" },
  { name: "deploy.yml", content: "privileged: true\nhostNetwork: true\ncapabilities:\n  add: ['ALL']" },
  { name: "src/security.ts", content: "logger.info(email); createHash('md5'); createCipheriv('aes-256-cbc', key, Buffer.alloc(16, 0));" }
]);

const record: TargetRecord = {
  challenge: {
    id: "controlled-expanded-coverage-2026",
    target: "https://controlled.webscan.example/",
    hostname: "controlled.webscan.example",
    token: "controlled-fixture-only",
    challengePath: "/.well-known/webscan-verification.txt",
    instructions: "Controlled fixture generated locally for regression validation only."
  },
  verifiedAt: "2026-08-20T16:00:00.000Z",
  ownerEvidence
};

const response: SafeResponse = {
  url: record.challenge.target,
  status: 200,
  headers: new Headers({
    "set-cookie": "session=redacted-value; Path=/",
    "access-control-allow-origin": "*",
    "access-control-allow-credentials": "true"
  }),
  html: '<!doctype html><html><body><form action="http://controlled.webscan.example/sign-in"></form><script src="http://assets.webscan.example/app.js"></script><script>localStorage.setItem("token", value)</script></body></html>'
};

const report = createReport(record, response);
await writeFile("/tmp/webscan-expanded-controlled-audit.json", JSON.stringify(report, null, 2), "utf8");
console.log(`Generated controlled expanded audit with ${report.findings.filter((item) => item.status === "attention").length} evidence-backed attention findings.`);
