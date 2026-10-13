import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import { generateHtmlReport } from "../scripts/generate-html-report.mts";
import { aggregateStatus } from "../scripts/aggregate-status.mts";

describe("Phase 14c: Extended Panels and Compliance Register", () => {
  it("renders all extended panels, KPI cards, and compliance register correctly", async () => {
    // 1. Ensure reports/status.json exists
    await aggregateStatus();

    // 2. Generate extended report
    const htmlPath = await generateHtmlReport("reports/status.json");
    assert.ok(existsSync(htmlPath), "Report must exist");

    const html = readFileSync(htmlPath, "utf-8");

    // P14C-001: Consensus panel & alert timeline
    assert.ok(html.includes("Zone 6: Consensus Attack Monitoring"), "Must contain Zone 6 panel");
    assert.ok(html.includes("SELFISH_MINING_PRIVATE_FORK"), "Must render consensus anomaly alert");
    assert.ok(html.includes("ALERT-CN-101"), "Must render alert ID");

    // P14C-002: Wallet audit & key schemes
    assert.ok(html.includes("Zone 7: Wallet Audit"), "Must contain Zone 7 panel");
    assert.ok(html.includes("MPC_3_OF_5_THRESHOLD"), "Must show MPC key scheme");
    assert.ok(html.includes("HSM_PKCS11_EMULATED"), "Must show HSM key scheme");

    // P14C-003: Forensic case timeline
    assert.ok(html.includes("Zone 5: Forensic Cases"), "Must contain Zone 5 panel");
    assert.ok(html.includes("CASE-FR-001"), "Must show forensic case ID");
    assert.ok(html.includes("Volatile memory and state logs captured"), "Must show redacted summary");

    // P14C-004: Executive KPI cards
    assert.ok(html.includes("Total Active Findings"), "Must contain Total Active Findings KPI");
    assert.ok(html.includes("Consensus Alerts"), "Must contain Consensus Alerts KPI");
    assert.ok(html.includes("Benchmark F1 Score"), "Must contain Benchmark F1 Score KPI");

    // P14C-005: Safe summary templates (strengths, flaws, recommended actions)
    assert.ok(html.includes("Systemic Strengths &amp; Active Safeguards") || html.includes("Systemic Strengths & Active Safeguards"), "Must render Strengths section");
    assert.ok(html.includes("Identified Flaws &amp; Vulnerabilities") || html.includes("Identified Flaws & Vulnerabilities"), "Must render Flaws section");
    assert.ok(html.includes("Recommended Actions"), "Must render Recommended Actions");

    // P14C-006: 21-col / Zone 8 Compliance Register
    assert.ok(html.includes("Zone 8: Regulatory Compliance Register"), "Must contain Zone 8 panel");
    assert.ok(html.includes("SDN MATCH"), "Must render sanctions match status");
    assert.ok(html.includes("ZK-VERIFIED (PEDERSEN)"), "Must render ZK attestation status");
    assert.ok(html.includes("DRAFT_PENDING_REVIEW"), "Must render HITL gate status");
  });
});
