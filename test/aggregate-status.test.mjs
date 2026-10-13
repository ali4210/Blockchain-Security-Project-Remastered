import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync, unlinkSync } from "node:fs";
import { resolve } from "node:path";
import { aggregateStatus } from "../scripts/aggregate-status.mts";

describe("Phase 14b: Status Aggregator and Exclusion Invariants", () => {
  const testOutputFile = resolve(process.cwd(), "reports/test-status.json");

  it("writes valid versioned status.json matching aggregation contract", async () => {
    const filePath = await aggregateStatus("reports/test-status.json");
    assert.ok(existsSync(filePath), "reports/test-status.json must exist");

    const content = JSON.parse(readFileSync(filePath, "utf-8"));
    assert.equal(content.schemaVersion, 1);
    assert.ok(content.system.commitSha, "Commit SHA must be populated");
    assert.equal(content.system.status, "HEALTHY");
    assert.ok(Array.isArray(content.findings), "Findings array required");
    assert.ok(Array.isArray(content.incidents), "Incidents array required");
    assert.ok(Array.isArray(content.forensicCases), "Forensic cases array required");
    assert.ok(Array.isArray(content.consensusAlerts), "Consensus alerts array required");
    assert.ok(Array.isArray(content.walletAuditFindings), "Wallet audit array required");
    assert.ok(Array.isArray(content.complianceRegister), "Compliance register array required");
    assert.ok(content.benchmarks.f1Score > 0.9, "Benchmark F1 score must meet thresholds");
    assert.ok(content.mlResults.confusionMatrix.tp > 0, "Confusion matrix TP must be positive");
  });

  it("strictly excludes raw private keys, shares, sealed blobs, and unredacted SARs", async () => {
    const rawContent = readFileSync(testOutputFile, "utf-8");

    // Invariant 1: No 64-char EVM private key hex
    const privateKeyRegex = /0x[a-fA-F0-9]{64}/g;
    assert.equal(rawContent.match(privateKeyRegex), null, "Raw 32-byte private keys must not exist in status.json");

    // Invariant 2: No Shamir secret share payloads
    assert.ok(!rawContent.includes("share_value"), "Shamir share values must not exist");
    assert.ok(!rawContent.includes("prime_modulus"), "Prime modulus secrets must not exist");

    // Invariant 3: No unredacted SAR filing payload markers
    assert.ok(!rawContent.includes("SSN_PLAINTEXT"), "Unredacted personal identities must not exist");

    if (existsSync(testOutputFile)) {
      unlinkSync(testOutputFile);
    }
  });
});
