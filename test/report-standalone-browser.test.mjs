import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import { generateHtmlReport } from "../scripts/generate-html-report.mts";
import { aggregateStatus } from "../scripts/aggregate-status.mts";

describe("Phase 14e: Standalone Browser Rendering Invariants (P14E-004)", () => {
  it("verifies standalone browser compatibility without server or CDN", async () => {
    await aggregateStatus();
    const reportPath = await generateHtmlReport();
    assert.ok(existsSync(reportPath), "Report must exist on disk");

    const html = readFileSync(reportPath, "utf-8");

    // 1. Valid DOCTYPE and HTML envelope
    assert.ok(html.startsWith("<!DOCTYPE html>"), "Must start with standard HTML5 DOCTYPE");
    assert.ok(html.includes("<html lang=\"en\">"), "Must declare HTML language");
    assert.ok(html.includes("</html>"), "Must close HTML envelope");

    // 2. Air-gapped zero CDN enforcement (no external script or link tags)
    assert.ok(!html.includes("<script src=\"http"), "No remote script sources allowed");
    assert.ok(!html.includes("<link rel=\"stylesheet\" href=\"http"), "No remote stylesheet sources allowed");
    assert.ok(!html.includes("@import url("), "No remote CSS imports allowed");

    // 3. Inline SVG graphics intact
    assert.ok(html.includes("<svg width=\"120\" height=\"120\""), "Inline SVG donut chart must be present");
    assert.ok(html.includes("stroke-dasharray="), "SVG donut circumference slices must be defined");

    // 4. Print / PDF layout support
    assert.ok(html.includes("@media print"), "Must include print stylesheet rules");
    assert.ok(html.includes("window.print()"), "Must include print export trigger");

    // 5. Executive components present
    assert.ok(html.includes("kpi-grid"), "Must render KPI grid");
    assert.ok(html.includes("takeaway-grid"), "Must render automated takeaway synthesis grid");
    assert.ok(html.includes("filterFindings()"), "Must render live client-side search logic");
  });
});
