import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { join, relative, resolve } from "node:path";

// STRIDE coverage scorecard: self-verifies that the file:line evidence in
// config/stride-coverage-map.json still exists/is current (staleness check),
// plus drift detection against config/stride-known-files.json. Purely
// additive scoring metadata -- NOT a security check, NOT in
// pipeline-verdict.py's REQUIRED list, cannot affect PASS/HALT. Honest-failure
// pattern (matches src/observability/threat_intel.py and
// scripts/run-enrichment.mts): any failure is logged loudly and recorded as
// a visible "error" status, never silently swallowed, never allowed to throw
// and kill the pipeline.

interface MapEntry { file: string; line: number; description: string; }
type MapCategories = Record<string, MapEntry[]>;

const ROOT = process.cwd();
const MAP_PATH = resolve(ROOT, "config/stride-coverage-map.json");
const SNAPSHOT_PATH = resolve(ROOT, "config/stride-known-files.json");
const OUTPUT = resolve(ROOT, "reports/scanners/stride-coverage.json");
const CROSSWALK_DOC = resolve(ROOT, "docs/STRIDE-CROSSWALK.md");
const CATEGORY_ORDER = [
  "Spoofing", "Tampering", "Repudiation",
  "Information Disclosure", "Denial of Service", "Elevation of Privilege",
];
const SOURCE_ROOTS = ["src", "scripts", "contracts"];
const SOURCE_EXTENSIONS = [".py", ".mts", ".cjs", ".ts", ".js", ".sh", ".sol"];
const EXCLUDE_DIRS = new Set(["node_modules", "__pycache__", ".git"]);

function writeOutput(
  status: string,
  categories: Record<string, { covered: boolean; entries: any[] }>,
  categoriesCovered: number,
  unreviewed: string[],
  staleEntries: any[],
  baselineEstablished: boolean,
): void {
  mkdirSync(resolve(ROOT, "reports/scanners"), { recursive: true });
  writeFileSync(
    OUTPUT,
    JSON.stringify({
      status, categories_covered: categoriesCovered, categories,
      stale_entries: staleEntries, unreviewed_files: unreviewed,
      baseline_established: baselineEstablished,
      generated_at: new Date().toISOString(),
    }, null, 2) + "\n"
  );
}

function fail(reason: string): void {
  console.error(`[!] [ZONE 9] STRIDE coverage verification NOT run: ${reason}`);
  writeOutput("error", {}, 0, [], [], false);
}

function walkSourceFiles(): string[] {
  const results: string[] = [];
  function walk(dir: string): void {
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (EXCLUDE_DIRS.has(entry.name)) continue;
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(full);
      } else if (SOURCE_EXTENSIONS.some((ext) => entry.name.endsWith(ext))) {
        results.push(relative(ROOT, full));
      }
    }
  }
  for (const root of SOURCE_ROOTS) walk(resolve(ROOT, root));
  return results;
}

function generateCrosswalkDoc(map: MapCategories): void {
  let md = "# STRIDE Threat-Model Crosswalk\n\n";
  md += "Generated automatically from `config/stride-coverage-map.json` by `scripts/verify-stride-coverage.mts` on every pipeline run. ";
  md += "This document and the live HTML report's \"STRIDE Coverage Scorecard\" section are rendered from the exact same source file and cannot drift apart. ";
  md += "Do not hand-edit this file -- edit the JSON map instead.\n\n";
  for (const cat of CATEGORY_ORDER) {
    const entries = map[cat] || [];
    md += `## ${cat}\n\n`;
    if (entries.length === 0) {
      md += "_No real, verified control in this repo maps to this category._\n\n";
      continue;
    }
    md += "| File:Line | Description |\n|---|---|\n";
    for (const e of entries) {
      md += `| \`${e.file}:${e.line}\` | ${e.description} |\n`;
    }
    md += "\n";
  }
  writeFileSync(CROSSWALK_DOC, md, "utf-8");
}

function main(): void {
  console.log("[+] [ZONE 9] Verifying STRIDE coverage scorecard (self-check of config/stride-coverage-map.json)...");

  if (!existsSync(MAP_PATH)) {
    fail(`${MAP_PATH} does not exist`);
    return;
  }

  let mapRaw: any;
  try {
    mapRaw = JSON.parse(readFileSync(MAP_PATH, "utf-8"));
  } catch (err) {
    fail(`failed to parse ${MAP_PATH}: ${(err as Error).message}`);
    return;
  }
  const map: MapCategories = mapRaw.categories || {};

  const staleEntries: any[] = [];
  const categories: Record<string, { covered: boolean; entries: any[] }> = {};
  let categoriesCovered = 0;

  for (const cat of CATEGORY_ORDER) {
    const rawEntries: MapEntry[] = map[cat] || [];
    const checked = rawEntries.map((e) => {
      const fullPath = resolve(ROOT, e.file);
      let stale = false;
      let staleReason = "";
      if (!existsSync(fullPath)) {
        stale = true;
        staleReason = "file no longer exists";
      } else {
        try {
          const lineCount = readFileSync(fullPath, "utf-8").split("\n").length;
          if (e.line > lineCount) {
            stale = true;
            staleReason = `line ${e.line} beyond current file length (${lineCount})`;
          }
        } catch (err) {
          stale = true;
          staleReason = `failed to read file: ${(err as Error).message}`;
        }
      }
      if (stale) staleEntries.push({ category: cat, file: e.file, line: e.line, reason: staleReason });
      return { ...e, stale };
    });
    const covered = checked.some((e) => !e.stale);
    if (covered) categoriesCovered++;
    categories[cat] = { covered, entries: checked };
  }

  // Drift detection against the last snapshot. A missing snapshot means this
  // is the first time this check has ever run -- there is no prior baseline
  // to have drifted from, so this run establishes the baseline rather than
  // reporting the entire existing codebase as "unreviewed."
  const baselineEstablished = !existsSync(SNAPSHOT_PATH);
  const currentFiles = walkSourceFiles();
  const referencedFiles = new Set<string>();
  for (const cat of CATEGORY_ORDER) for (const e of (map[cat] || [])) referencedFiles.add(e.file);

  let previousSnapshot: Record<string, { mtimeMs: number; size: number }> = {};
  if (!baselineEstablished) {
    try {
      previousSnapshot = JSON.parse(readFileSync(SNAPSHOT_PATH, "utf-8"));
    } catch {
      previousSnapshot = {};
    }
  }

  const unreviewed: string[] = [];
  const newSnapshot: Record<string, { mtimeMs: number; size: number }> = {};
  for (const relPath of currentFiles) {
    const full = resolve(ROOT, relPath);
    let stat;
    try {
      stat = statSync(full);
    } catch {
      continue;
    }
    const current = { mtimeMs: stat.mtimeMs, size: stat.size };
    newSnapshot[relPath] = current;
    if (baselineEstablished) continue;
    const prev = previousSnapshot[relPath];
    const changed = !prev || prev.mtimeMs !== current.mtimeMs || prev.size !== current.size;
    if (changed && !referencedFiles.has(relPath)) {
      unreviewed.push(relPath);
    }
  }
  writeFileSync(SNAPSHOT_PATH, JSON.stringify(newSnapshot, null, 2) + "\n", "utf-8");

  try {
    generateCrosswalkDoc(map);
  } catch (err) {
    console.error(`[!] [ZONE 9] STRIDE crosswalk doc generation failed (non-fatal): ${(err as Error).message}`);
  }

  const status = staleEntries.length > 0 ? "stale_entries" : "ok";
  writeOutput(status, categories, categoriesCovered, unreviewed, staleEntries, baselineEstablished);
  console.log(`    -> STRIDE coverage: ${categoriesCovered}/6 categories covered, ${staleEntries.length} stale entry(ies), ${unreviewed.length} unreviewed file(s)${baselineEstablished ? " (baseline established this run)" : ""}.`);
}

try {
  main();
} catch (err) {
  fail(`unexpected error: ${(err as Error).message}`);
}
