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
  const fixture = join(root, "contracts/solidity/VulnerableVault.sol");
  const info = lstatSync(fixture);
  if (!info.isFile() || info.isSymbolicLink()) throw new Error("fixture-input");
  const bytes = readFileSync(fixture);
  const expected = "31a68c972361a3e537cd9b6107eb4efb7f47b77236958098db61dbefa184354a";
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
  process.exitCode = masked.status === "masked" ? 0
    : masked.status === "manual-review" ? 2 : 1;
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
