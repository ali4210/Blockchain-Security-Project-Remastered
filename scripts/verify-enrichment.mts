import assert from "node:assert/strict";
import { enrichFindings, mapFindingToGovernance } from "./enrich-findings.mts";

console.log("Running findings enrichment governance framework verification...");

// 1. Verify Reentrancy / Arbitrary Send Mapping
const reentrancyGov = mapFindingToGovernance("arbitrary-send-erc20", "slither", "sends ether to arbitrary caller");
assert.equal(reentrancyGov.mitreAttack.techniqueId, "T1565.002");
assert.equal(reentrancyGov.cisControls.controlId, "CIS-16.1");
assert.equal(reentrancyGov.iso27001.controlId, "A.8.28");
assert.equal(reentrancyGov.cset.category, "Software Development");

// 2. Verify Access Control Bypass Mapping
const accessGov = mapFindingToGovernance("unprotected-owner-change", "mythril", "unrestricted access control");
assert.equal(accessGov.mitreAttack.techniqueId, "T1078.004");
assert.equal(accessGov.cisControls.controlId, "CIS-06.1");
assert.equal(accessGov.iso27001.controlId, "A.8.3");

// 3. Verify Lynis Host Governance Mapping
const lynisGov = mapFindingToGovernance("AUTH-9230", "lynis", "system hardening recommendation");
assert.equal(lynisGov.mitreAttack.techniqueId, "T1059.004");
assert.equal(lynisGov.cisControls.controlId, "CIS-04.1");
assert.equal(lynisGov.iso27001.controlId, "A.8.9");

// 4. Verify Full Array Enrichment
const sampleFindings = [
  {
    id: "FINDING-SLITHER-0001",
    sourceTool: "slither",
    severity: "HIGH",
    title: "arbitrary-send-erc20",
    description: "VulnerableVault sends ether to caller",
    target: "VulnerableVault",
    dread: { score: 7.8 },
  },
  {
    id: "FINDING-GENERIC-0002",
    sourceTool: "custom",
    severity: "LOW",
    title: "unspecified-notice",
    description: "informational finding",
    target: "unknown",
  },
];

const enriched = enrichFindings(sampleFindings);
assert.equal(enriched.length, 2);
assert.equal(enriched[0].governance.mitreAttack.techniqueId, "T1565.002");
assert.equal(enriched[1].governance.mitreAttack.techniqueId, "T1190"); // Fallback

// 5. Edge cases: Empty and null inputs
assert.deepEqual(enrichFindings([]), []);
assert.deepEqual(enrichFindings(null as unknown as unknown[]), []);

console.log("All governance enrichment assertions passed (5/5).");
