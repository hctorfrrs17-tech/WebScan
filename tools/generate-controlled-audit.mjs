import { readFile, mkdir, writeFile } from "node:fs/promises";
import { createReportExport } from "../src/reportExport.ts";

const source = process.argv[2];
if (!source) throw new Error("Provide the source report JSON path.");

const report = JSON.parse(await readFile(source, "utf8"));
await mkdir("examples", { recursive: true });
await writeFile("examples/controlled-audit-report.json", JSON.stringify(report, null, 2));

for (const format of ["markdown", "html"]) {
  const artifact = createReportExport(report, format);
  const output = format === "markdown" ? "examples/controlled-audit-report.md" : "examples/controlled-audit-report.html";
  await writeFile(output, artifact.content);
}

console.log("Generated controlled audit artifacts in examples/.");
