import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { computeDreadScore } from "./normalize-reports.mts";

// DREAD scoring (5-factor vector: Damage/Reproducibility/Exploitability/
// Affected Users/Discoverability), computed from this run's own real
// SAST/symbolic findings via the already-tested computeDreadScore() in
// normalize-reports.mts. Purely additive reporting metadata -- NOT a
// security check, NOT in pipeline-verdict.py's REQUIRED list, and it can
// never affect PASS/HALT. A separate, simpler severity-based DREAD proxy
// already feeds Grafana (scripts/ship-siem-telemetry.py's
// blockchain_soc_dread_score gauge, derived from run-all-e2e.sh's own
// IMPACT_DREAD lookup) -- that pipeline is untouched by this script.
// Honest-failure pattern (matches src/observability/threat_intel.py and
// scripts/run-enrichment.mts): any failure is logged loudly and recorded as
// a visible "not_run"/"error" status, never silently swallowed, never
// allowed to throw and kill the pipeline.

const SAST_REPORT = resolve(process.cwd(), "reports/sast-symbolic-report.json");
const OUTPUT = resolve(process.cwd(), "reports/dread-scoring-report.json");
const SCANNERS_DIR = resolve(process.cwd(), "reports/scanners");

function writeScannerResult(status: "ok" | "not_run" | "error", detail: string, count: number): void {
  mkdirSync(SCANNERS_DIR, { recursive: true });
  writeFileSync(
    join(SCANNERS_DIR, "dread-scoring.json"),
    JSON.stringify({
      name: "dread-scoring", tool: "normalize-reports.mts:computeDreadScore", status,
      version: null, target: "sast-symbolic-report.json",
      counts: { scored: count }, raw_report: null, raw_sha256: null,
      detail, finished_at: new Date().toISOString(),
    }, null, 2) + "\n"
  );
}

function fail(reason: string): void {
  console.error(`[!] [ZONE 9] DREAD scoring NOT run: ${reason}`);
  writeFileSync(OUTPUT, JSON.stringify({ status: "not_run", reason, scored: [] }, null, 2) + "\n");
  writeScannerResult("not_run", reason, 0);
}

function main(): void {
  console.log("[+] [ZONE 9] Computing 5-factor DREAD vectors (Damage/Reproducibility/Exploitability/Affected/Discoverability) from this run's real SAST/symbolic findings...");

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
    fail("sast-symbolic-report.json contains zero findings this run -- nothing to score");
    return;
  }

  let scored: any[];
  try {
    scored = rawFindings.map((f: any, i: number) => {
      const tool = f.engine || "unknown";
      const severity = f.impact || "MEDIUM";
      const dread = computeDreadScore(severity, tool);
      return {
        id: `SAST-${i}-${f.check || "unknown"}`,
        sourceTool: tool,
        severity,
        title: f.check || "Security Finding",
        description: f.description || "",
        target: f.target || "unknown",
        dread,
      };
    });
  } catch (err) {
    fail(`computeDreadScore() threw: ${(err as Error).message}`);
    return;
  }

  writeFileSync(OUTPUT, JSON.stringify({ status: "ok", scored }, null, 2) + "\n");
  writeScannerResult("ok", `${scored.length} finding(s) scored`, scored.length);
  console.log(`    -> Computed DREAD vectors for ${scored.length} finding(s).`);
}

try {
  main();
} catch (err) {
  // Last-resort net: even an unexpected bug here must stay loud, not kill the pipeline.
  fail(`unexpected error: ${(err as Error).message}`);
}
