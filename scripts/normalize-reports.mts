import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

export interface DreadVector {
  damage: number;
  reproducibility: number;
  exploitability: number;
  affectedUsers: number;
  discoverability: number;
  score: number;
}

export interface NormalizedFinding {
  id: string;
  sourceTool: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL";
  title: string;
  description: string;
  target: string;
  dread: DreadVector;
  rawDetails: Record<string, unknown>;
}

export function computeDreadScore(
  severity: string,
  tool: string,
  overrides?: Partial<Omit<DreadVector, "score">>
): DreadVector {
  const normSev = severity.toUpperCase();
  let baseD = 5;
  let baseR = 5;
  let baseE = 5;
  let baseA = 5;
  let baseDisc = 5;

  switch (normSev) {
    case "CRITICAL":
      baseD = 9.5;
      baseR = 8.5;
      baseE = 9.0;
      baseA = 9.0;
      baseDisc = 8.0;
      break;
    case "HIGH":
      baseD = 8.0;
      baseR = 7.5;
      baseE = 7.0;
      baseA = 7.5;
      baseDisc = 7.0;
      break;
    case "MEDIUM":
      baseD = 5.5;
      baseR = 6.0;
      baseE = 5.0;
      baseA = 5.5;
      baseDisc = 6.0;
      break;
    case "LOW":
      baseD = 3.0;
      baseR = 4.0;
      baseE = 3.5;
      baseA = 3.0;
      baseDisc = 5.0;
      break;
    case "INFORMATIONAL":
    default:
      baseD = 1.0;
      baseR = 2.0;
      baseE = 2.0;
      baseA = 1.5;
      baseDisc = 4.0;
      break;
  }

  // Tool-specific calibrations
  if (tool.toLowerCase().includes("slither") || tool.toLowerCase().includes("mythril")) {
    baseE = Math.min(10, baseE + 0.5);
  } else if (tool.toLowerCase().includes("lynis")) {
    baseA = Math.max(1, baseA - 0.5);
  }

  const d = Math.max(0, Math.min(10, overrides?.damage ?? baseD));
  const r = Math.max(0, Math.min(10, overrides?.reproducibility ?? baseR));
  const e = Math.max(0, Math.min(10, overrides?.exploitability ?? baseE));
  const a = Math.max(0, Math.min(10, overrides?.affectedUsers ?? baseA));
  const disc = Math.max(0, Math.min(10, overrides?.discoverability ?? baseDisc));

  const rawScore = (d + r + e + a + disc) / 5.0;
  const score = Math.round(rawScore * 10) / 10;

  return {
    damage: d,
    reproducibility: r,
    exploitability: e,
    affectedUsers: a,
    discoverability: disc,
    score,
  };
}

export function normalizeReports(rawFindings: unknown[]): NormalizedFinding[] {
  if (!Array.isArray(rawFindings)) {
    return [];
  }

  const normalized: NormalizedFinding[] = [];

  for (let i = 0; i < rawFindings.length; i++) {
    const item = rawFindings[i];
    if (!item || typeof item !== "object") continue;

    const record = item as Record<string, unknown>;
    const tool = String(record.sourceTool || record.tool || record.source || "generic").toLowerCase();
    let sev: NormalizedFinding["severity"] = "MEDIUM";
    let title = "Security Finding";
    let desc = "";
    let target = "contract";

    // 1. Slither normalization
    if (record.check || record.impact) {
      title = String(record.check || "Slither Detector");
      const impact = String(record.impact || "").toUpperCase();
      if (impact === "HIGH") sev = "HIGH";
      else if (impact === "MEDIUM") sev = "MEDIUM";
      else if (impact === "LOW") sev = "LOW";
      else if (impact === "INFORMATIONAL") sev = "INFORMATIONAL";
      desc = String(record.description || record.title || "");
      target = String(record.contract || record.filename || "contract");
    }
    // 2. Mythril normalization
    else if (record.swc_id || record.issue) {
      title = String(record.title || record.swc_id || "Mythril Issue");
      const severity = String(record.severity || "").toUpperCase();
      if (severity === "HIGH") sev = "HIGH";
      else if (severity === "MEDIUM") sev = "MEDIUM";
      else if (severity === "LOW") sev = "LOW";
      desc = String(record.description || "");
      target = String(record.contract || record.address || "contract");
    }
    // 3. Lynis governance normalization
    else if (record.finding_id || record.test_id) {
      title = `Lynis Baseline: ${String(record.finding_id || record.test_id)}`;
      sev = "LOW";
      desc = String(record.details || record.description || "");
      target = "host_governance";
    }
    // 4. Fallback / generic schema
    else {
      title = String(record.title || record.name || "Generic Security Issue");
      const candidateSev = String(record.severity || "MEDIUM").toUpperCase();
      if (["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"].includes(candidateSev)) {
        sev = candidateSev as NormalizedFinding["severity"];
      }
      desc = String(record.description || record.detail || "");
      target = String(record.target || record.file || "unknown");
    }

    const dread = computeDreadScore(sev, tool);
    const id = `FINDING-${tool.toUpperCase()}-${String(i + 1).padStart(4, "0")}`;

    normalized.push({
      id,
      sourceTool: tool,
      severity: sev,
      title,
      description: desc,
      target,
      dread,
      rawDetails: record,
    });
  }

  return normalized;
}

// CLI entry point
if (import.meta.url.endsWith(process.argv[1] || "")) {
  const args = process.argv.slice(2);
  if (args.includes("--help") || args.includes("-h")) {
    console.log("Usage: tsx scripts/normalize-reports.mts [--input <file>] [--output <file>]");
    console.log("Normalizes raw security tool findings and calculates DREAD scores.");
    process.exit(0);
  }

  const inputIdx = args.indexOf("--input");
  const outputIdx = args.indexOf("--output");

  if (inputIdx !== -1 && args[inputIdx + 1]) {
    const inputPath = resolve(args[inputIdx + 1]);
    const rawContent = JSON.parse(readFileSync(inputPath, "utf-8"));
    const findings = Array.isArray(rawContent) ? rawContent : rawContent.findings || [];
    const normalized = normalizeReports(findings);

    if (outputIdx !== -1 && args[outputIdx + 1]) {
      const outputPath = resolve(args[outputIdx + 1]);
      writeFileSync(outputPath, JSON.stringify(normalized, null, 2), "utf-8");
      console.log(`Normalized ${normalized.length} findings to ${outputPath}`);
    } else {
      console.log(JSON.stringify(normalized, null, 2));
    }
  }
}
