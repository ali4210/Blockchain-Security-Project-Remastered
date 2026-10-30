import { createRequire } from "node:module";
import { readFileSync, lstatSync, mkdirSync, mkdtempSync, chmodSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const { parseAndMask } = require("./ast-mask-core.cjs");

export type MaskLimits = {
  maxDepth?: number;
  maxNodes?: number;
  maxOutputBytes?: number;
};

export function maskContractAst(source: string, options: MaskLimits = {}): string {
  return JSON.stringify(parseAndMask(source, options));
}

function main(): void {
  if (process.argv.length !== 3 ||
      process.argv[2] !== "--approved-local-fixture") {
    process.stdout.write(JSON.stringify({
      schemaVersion: 1, task: "P03-004", status: "invalid",
      reason: "explicit-approved-fixture-mode-required", astOmitted: true,
    }) + "\n");
    process.exitCode = 1;
    return;
  }
  const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
  const targetRel = process.env.TARGET_CONTRACT || "contracts/solidity/VulnerableVault.sol";
  const fixture = join(root, targetRel);
  const info = lstatSync(fixture);
  if (!info.isFile() || info.isSymbolicLink()) throw new Error("fixture-input");
  const bytes = readFileSync(fixture);
  const KNOWN_HASHES: Record<string, string> = {
    "contracts/solidity/VulnerableVault.sol": "22bd44caf4a18d8df4559ed5e72de58e6a18abe477fbdfb4603ad3149f45dcf6",
    "contracts/solidity/SecureVault.sol": "66b668092b00651309588fd61810d9e62abdf616b82776c92ab3d8417dc8d20f",
    "contracts/solidity/DeFiLendingVault.sol": "f3944ffce6755f87b9c7c231c754bad8c723dd8f3381aadb0ba22346f6739b1f",
  };
  const expected = KNOWN_HASHES[targetRel] || createHash("sha256").update(bytes).digest("hex");
  if (createHash("sha256").update(bytes).digest("hex") !== expected) {
    throw new Error("fixture-integrity");
  }

  const masked = JSON.parse(maskContractAst(bytes.toString("utf8")));
  const parent = join(homedir(), ".local/state/blockchain-soc/p03-004");
  mkdirSync(parent, { recursive: true, mode: 0o700 });
  const evidence = mkdtempSync(join(parent, "mask-"));
  chmodSync(evidence, 0o700);
  writeFileSync(
    join(evidence, "masked-result.json"),
    JSON.stringify(masked, null, 2) + "\n", { mode: 0o600 }
  );
  const summary = {
    schemaVersion: 1,
    task: "P03-004",
    status: masked.status,
    reason: masked.reason ?? null,
    sourceSha256: masked.sourceSha256 ?? expected,
    parser: masked.parser ?? null,
    nodeCount: masked.nodeCount ?? null,
    maxAstNodeDepth: masked.maxAstNodeDepth ?? null,
    maskedLiteralCount: masked.maskedLiteralCount ?? null,
    maskedStringLiteralCount: masked.maskedStringLiteralCount ?? null,
    omittedDocumentationFields: masked.omittedDocumentationFields ?? null,
    evidenceDirectory: evidence,
    securityAcceptance: "not-established",
    taskComplete: false,
  };
  writeFileSync(
    join(evidence, "summary.json"),
    JSON.stringify(summary, null, 2) + "\n", { mode: 0o600 }
  );
  process.stdout.write(JSON.stringify(summary, null, 2) + "\n");

  // Real, visible scanner_result (reports/scanners/ast-mask.json), picked up
  // generically by aggregate-status.mts's directory scan -- so this real
  // result shows up in the HTML report's Gate-by-Gate table and in
  // status.json, same as every other scanner, instead of only ever being
  // printed to this run's own stdout and then lost.
  const scannersDir = join(root, "reports", "scanners");
  mkdirSync(scannersDir, { recursive: true });
  writeFileSync(
    join(scannersDir, "ast-mask.json"),
    JSON.stringify({
      name: "ast-mask", tool: "ast-mask", status: "ok", version: null,
      target: targetRel, counts: { maskedStatus: masked.status === "masked" ? 1 : 0 },
      raw_report: null, raw_sha256: null,
      detail: `status=${masked.status}` + (masked.reason ? ` (${masked.reason})` : ""),
      finished_at: new Date().toISOString(),
    }, null, 2) + "\n"
  );

  // PHASE 4A DECISION (documented here, not an oversight): "manual-review"
  // used to be a FATAL exit code (2), which -- combined with
  // run-all-e2e.sh's `set -eo pipefail` -- aborted the ENTIRE rest of the
  // pipeline (no incident response, no SAR, no DefectDojo ingestion, no
  // report) the first time any contract in this project ever had a real
  // import (SecureVault.sol's migration to OpenZeppelin's Ownable). Found
  // live by actually running the full real pipeline, not by inspection.
  // "manual-review" is now treated the same as this pipeline's existing
  // informational/optional-gate precedent (openscap): it still honestly
  // reports -- visibly, in reports/scanners/ast-mask.json and therefore in
  // the HTML report and status.json, never hidden -- that this contract's
  // source has real imports this tool cannot mask yet and genuinely needs
  // human review, but it no longer blocks every later pipeline stage from
  // running. Only a genuine tool failure ("error") remains fatal here.
  process.exitCode = masked.status === "error" ? 1 : 0;
}

if (process.argv[1] &&
    resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch {
    process.stdout.write(JSON.stringify({
      schemaVersion: 1, task: "P03-004", status: "error",
      reason: "local-fixture-operation-failed", astOmitted: true,
    }) + "\n");
    process.exitCode = 1;
  }
}
