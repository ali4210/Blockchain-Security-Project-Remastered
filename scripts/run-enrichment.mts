import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { enrichFindings } from "./enrich-findings.mts";

// Governance-framework enrichment (MITRE ATT&CK / CIS Controls v8 / ISO 27001).
// Purely additive reporting metadata -- NOT a security check, NOT in
// pipeline-verdict.py's REQUIRED list, and it can never affect PASS/HALT.
// Honest-failure pattern (matches src/observability/threat_intel.py): any
// failure is logged loudly to stdout/stderr and recorded as a visible
// "not_run"/"error" status in both the scanner result and the report JSON
// -- never silently swallowed, never allowed to throw and kill the pipeline.

const SAST_REPORT = resolve(process.cwd(), "reports/sast-symbolic-report.json");
const OUTPUT = resolve(process.cwd(), "reports/enriched-findings-report.json");
const SCANNERS_DIR = resolve(process.cwd(), "reports/scanners");

function writeScannerResult(status: "ok" | "not_run" | "error", detail: string, count: number): void {
  mkdirSync(SCANNERS_DIR, { recursive: true });
  writeFileSync(
    join(SCANNERS_DIR, "governance-enrichment.json"),
    JSON.stringify({
      name: "governance-enrichment", tool: "enrich-findings.mts", status,
      version: null, target: "sast-symbolic-report.json",
      counts: { enriched: count }, raw_report: null, raw_sha256: null,
      detail, finished_at: new Date().toISOString(),
    }, null, 2) + "\n"
  );
}

function fail(reason: string): void {
  console.error(`[!] [ZONE 9] Governance enrichment NOT run: ${reason}`);
  writeFileSync(OUTPUT, JSON.stringify({ status: "not_run", reason, enriched: [] }, null, 2) + "\n");
  writeScannerResult("not_run", reason, 0);
}

function main(): void {
  console.log("[+] [ZONE 9] Mapping this run's SAST/symbolic findings to MITRE ATT&CK / CIS Controls v8 / ISO 27001 (governance enrichment, informational only)...");

  if (!existsSync(SAST_REPORT)) {
    fail(`${SAST_REPORT} does not exist -- SAST/symbolic step did not produce a report this run`);
    return;
  }

  let raw: any;
  try {
    raw = JSON.parse(readFileSync(SAST_REPORT, "utf-8"));
  } catch (err) {
    fail(`failed to parse ${SAST_REPORT}: ${(err as Error).message}`);
    return;
  }

  const rawFindings = Array.isArray(raw?.findings) ? raw.findings : [];
  if (rawFindings.length === 0) {
    fail("sast-symbolic-report.json contains zero findings this run -- nothing to enrich");
    return;
  }

  // Adapt SAST/symbolic's real field names (engine/check/impact) to
  // enrichFindings()'s expected shape, inventing nothing.
  const adapted = rawFindings.map((f: any, i: number) => ({
    id: `SAST-${i}-${f.check || "unknown"}`,
    sourceTool: f.engine || "unknown",
    severity: f.impact || "MEDIUM",
    title: f.check || "Security Finding",
    description: f.description || "",
    target: f.target || "unknown",
    rawDetails: { owasp_category: f.owasp_category, confidence: f.confidence },
  }));

  let enriched;
  try {
    enriched = enrichFindings(adapted);
  } catch (err) {
    fail(`enrichFindings() threw: ${(err as Error).message}`);
    return;
  }

  writeFileSync(OUTPUT, JSON.stringify({ status: "ok", enriched }, null, 2) + "\n");
  writeScannerResult("ok", `${enriched.length} finding(s) mapped`, enriched.length);
  console.log(`    -> Enriched ${enriched.length} finding(s) with MITRE ATT&CK / CIS v8 / ISO 27001 mappings.`);
}

try {
  main();
} catch (err) {
  // Last-resort net: even an unexpected bug here must stay loud, not kill the pipeline.
  fail(`unexpected error: ${(err as Error).message}`);
}
