import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, unlinkSync, existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { generateHtmlReport } from "../scripts/generate-html-report.mts";

describe("Phase 14a: HTML Report Standalone Rendering", () => {
  const sampleJsonPath = resolve(process.cwd(), "reports/test-sanitized-sample.json");

  it("renders report correctly from sanitized sample JSON with full escaping", async () => {
    const samplePayload = {
      schemaVersion: 1,
      timestamp: "2026-10-13T06:00:00Z",
      system: {
        name: "Test Blockchain SOC",
        version: "1.0.0-test",
        commitSha: "abcdef1234567890",
        status: "HEALTHY",
      },
      metrics: {
        totalFindings: 2,
        criticalFindings: 1,
        highFindings: 1,
        mediumFindings: 0,
        lowFindings: 0,
        complianceScorePct: 100,
        activeConsensusAlerts: 0,
        forensicCasesSealed: 1,
      },
      findings: [
        {
          id: "TEST-001",
          rule_id: "INJECTION-TEST",
          zone: "ZONE_1_CONTRACTS",
          severity: "CRITICAL",
          title: "Malicious payload <script>alert(1)</script>",
          description: "Attempted prompt injection & unescaped quotes \"hello\"",
          target: "contracts/Test.sol",
          status: "MITIGATED",
        },
      ],
      zones: {
        "ZONE_1_CONTRACTS": {
          status: "PASS",
          testCount: 10,
          summary: "Verified with <safe> tags",
        },
      },
    };

    writeFileSync(sampleJsonPath, JSON.stringify(samplePayload, null, 2), "utf-8");

    const generatedPath = await generateHtmlReport(sampleJsonPath);
    assert.ok(existsSync(generatedPath), "Generated HTML report must exist on disk");

    const htmlContent = readFileSync(generatedPath, "utf-8");

    // Invariant 1: Ensure raw script tag is escaped
    assert.ok(!htmlContent.includes("<script>alert(1)</script>"), "Raw script injection must not exist in HTML");
    assert.ok(htmlContent.includes("&lt;script&gt;alert(1)&lt;/script&gt;"), "Script tag must be HTML-escaped");

    // Invariant 2: Ensure air-gapped zero CDN policy (no external scripts or links)
    assert.ok(!htmlContent.includes("https://cdn"), "No external CDN links allowed");
    assert.ok(!htmlContent.includes("http://"), "No unencrypted remote calls allowed");

    // Cleanup sample file
    if (existsSync(sampleJsonPath)) {
      unlinkSync(sampleJsonPath);
    }
  });
});
