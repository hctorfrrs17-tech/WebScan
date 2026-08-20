import { readFile, writeFile } from "node:fs/promises";
import { createPdfPrintDocument } from "../src/reportExport";
import type { AssessmentReport } from "../shared/types";

const [sourcePath, outputPath] = process.argv.slice(2);

if (!sourcePath || !outputPath) {
  throw new Error("Usage: tsx tools/render-controlled-pdf.ts <report.json> <output.html>");
}

const report = JSON.parse(await readFile(sourcePath, "utf8")) as AssessmentReport;
await writeFile(outputPath, createPdfPrintDocument(report), "utf8");
console.log(`Prepared printable report at ${outputPath}`);
