import assert from "node:assert/strict";
import { normalizeReports, computeDreadScore } from "./normalize-reports.mts";

console.log("Running report normalization & DREAD unit verification...");

// 1. DREAD score boundaries
const critical = computeDreadScore("CRITICAL", "slither");
assert(critical.score >= 8.0 && critical.score <= 10.0, "Critical DREAD score out of range");
assert(critical.damage >= 9.0, "Critical damage score out of range");

const info = computeDreadScore("INFORMATIONAL", "generic");
assert(info.score >= 0.0 && info.score <= 3.5, "Informational DREAD score out of range");
assert(info.damage <= 2.0, "Informational damage score out of range");

// 2. Slither normalization
const slitherInput = [
  {
    sourceTool: "slither",
    check: "arbitrary-send-erc20",
    impact: "High",
    description: "VulnerableVault sends ether to arbitrary caller",
    contract: "VulnerableVault",
  },
];
const slitherRes = normalizeReports(slitherInput);
assert.equal(slitherRes.length, 1);
assert.equal(slitherRes[0].id, "FINDING-SLITHER-0001");
assert.equal(slitherRes[0].severity, "HIGH");
assert.equal(slitherRes[0].title, "arbitrary-send-erc20");
assert(typeof slitherRes[0].dread.score === "number");
assert(slitherRes[0].dread.score >= 0.0 && slitherRes[0].dread.score <= 10.0);

// 3. Mythril normalization & empty handling
const mythrilInput = [
  {
    tool: "mythril",
    swc_id: "SWC-107",
    severity: "High",
    description: "State variable write after call",
    contract: "VulnerableVault",
  },
];
const mythrilRes = normalizeReports(mythrilInput);
assert.equal(mythrilRes.length, 1);
assert.equal(mythrilRes[0].title, "SWC-107");
assert.equal(mythrilRes[0].severity, "HIGH");

assert.deepEqual(normalizeReports([]), []);
assert.deepEqual(normalizeReports(null as unknown as unknown[]), []);

console.log("All report normalization and DREAD assertions passed (4/4).");
