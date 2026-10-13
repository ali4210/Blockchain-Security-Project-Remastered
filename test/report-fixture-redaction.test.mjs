import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync, unlinkSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import { aggregateStatus } from "../scripts/aggregate-status.mts";
import { generateHtmlReport } from "../scripts/generate-html-report.mts";

describe("Phase 14e: Fixture Redaction Security Invariants (P14E-002)", () => {
  const dirtyJsonPath = resolve(process.cwd(), "reports/dirty-fixture.json");

  it("strictly scrubs dirty forensic and compliance fixture payloads", async () => {
    const rawDirtyPayload = {
      schemaVersion: 1,
      timestamp: "2026-10-13T07:00:00Z",
      system: {
        name: "Security SOC Dirty Fixture",
        version: "1.0.0-test",
        commitSha: "0x1111111111111111111111111111111111111111",
        status: "HEALTHY",
      },
      metrics: {
        totalFindings: 1,
        criticalFindings: 1,
        highFindings: 0,
        mediumFindings: 0,
        lowFindings: 0,
        complianceScorePct: 100,
        activeConsensusAlerts: 0,
        forensicCasesSealed: 1,
      },
      findings: [
        {
          id: "DIRTY-001",
          rule_id: "RULE-SECRET-LEAK",
          zone: "ZONE_7_WALLET",
          severity: "CRITICAL",
          title: "Leaked EVM Key 0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d in log",
          description: "Raw ShamirShare payload share_value=99982314 prime_modulus=115792089237316195423570985008687907853269984665640564039457584007913129639935",
          target: "0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d",
          status: "MITIGATED",
        },
      ],
      incidents: [],
      forensicCases: [
        {
          caseId: "CASE-DIRTY",
          targetAddress: "0x1234567890123456789012345678901234567890",
          sealedArtifactsCount: 1,
          integrityVerified: true,
          redactedSummary: "BEGIN PRIVATE KEY MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC raw_secret payload",
        },
      ],
      consensusAlerts: [],
      walletAuditFindings: [],
      complianceRegister: [],
      benchmarks: { precision: 1.0, recall: 1.0, f1Score: 1.0, meanDetectionLatencyMs: 10.0 },
      mlResults: { confusionMatrix: { tp: 10, fp: 0, tn: 10, fn: 0 } },
      zones: {
        "ZONE_7_WALLET": { status: "PASS", testCount: 10, summary: "Tested with dirty fixture" },
      },
    };

    writeFileSync(dirtyJsonPath, JSON.stringify(rawDirtyPayload, null, 2), "utf-8");

    // Pass inputFile explicitly to sanitize dirty fixture
    const sanitizedOutput = await aggregateStatus("reports/dirty-fixture-sanitized.json", "reports/dirty-fixture.json");
    const sanitizedJson = readFileSync(sanitizedOutput, "utf-8");

    // Assert raw private key is completely scrubbed from JSON
    assert.ok(!sanitizedJson.includes("0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d"), "Raw private key must be redacted");
    assert.ok(sanitizedJson.includes("[REDACTED_PRIVATE_KEY]"), "Sanitizer marker must be present");

    // Assert raw Shamir share and key tags are scrubbed
    assert.ok(!sanitizedJson.includes("BEGIN PRIVATE KEY"), "Raw PEM key header must be redacted");
    assert.ok(!sanitizedJson.includes("raw_secret"), "Raw secret token must be redacted");

    // Generate HTML from the sanitized file
    const htmlReportPath = await generateHtmlReport("reports/dirty-fixture-sanitized.json");
    const html = readFileSync(htmlReportPath, "utf-8");

    // Assert no raw leaks appear in HTML presentation
    assert.ok(!html.includes("0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d"), "HTML must not contain raw private key");
    assert.ok(!html.includes("BEGIN PRIVATE KEY"), "HTML must not contain raw PEM header");

    // Cleanup dirty fixtures
    if (existsSync(dirtyJsonPath)) unlinkSync(dirtyJsonPath);
    if (existsSync(sanitizedOutput)) unlinkSync(sanitizedOutput);
  });
});
