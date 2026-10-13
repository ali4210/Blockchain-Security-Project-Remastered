import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";

describe("Phase 15c: Academic Paper and Scholarship Artifacts (P15C-001 through P15C-003)", () => {
  const paperPath = resolve(process.cwd(), "docs/PAPER.md");
  const sopPath = resolve(process.cwd(), "docs/STATEMENT_OF_PURPOSE.md");

  it("verifies IEEE/ACM-style paper draft exists with required academic sections", () => {
    assert.ok(existsSync(paperPath), "docs/PAPER.md must exist");
    const content = readFileSync(paperPath, "utf-8");

    const requiredSections = [
      "## Abstract",
      "## 1. Introduction",
      "## 2. Threat Model and Boundary Invariants",
      "## 3. System Architecture",
      "## 4. Empirical Evaluation & Benchmarking",
      "## 5. Privacy, Data Sovereignty, and Air-Gapped Isolation",
      "## 6. Conclusion",
    ];

    for (const section of requiredSections) {
      assert.ok(content.includes(section), `Paper must contain section: ${section}`);
    }
  });

  it("verifies statement of purpose asset exists and embeds exact empirical metrics", () => {
    assert.ok(existsSync(sopPath), "docs/STATEMENT_OF_PURPOSE.md must exist");
    const sop = readFileSync(sopPath, "utf-8");
    const paper = readFileSync(paperPath, "utf-8");

    const requiredMetrics = [
      "97.4%", // Precision & Recall
      "84.2%", // Autonomous PoC Pass Rate
      "8.4",   // MTTR seconds
      "100.0%", // Hash chain integrity
      "45.2 ms", // Time-to-timeline
      "96.0%", // IOC accuracy
    ];

    for (const metric of requiredMetrics) {
      assert.ok(sop.includes(metric), `SOP must embed exact measured metric: ${metric}`);
      assert.ok(paper.includes(metric), `Paper must embed exact measured metric: ${metric}`);
    }
  });

  it("proves academic artifacts enforce privacy, data sovereignty, and zero-secret invariants", () => {
    const forbiddenPatterns = [
      /BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY/,
      /0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d/,
    ];

    for (const file of [paperPath, sopPath]) {
      const text = readFileSync(file, "utf-8");
      for (const pattern of forbiddenPatterns) {
        assert.ok(!pattern.test(text), `Forbidden secret pattern detected in ${file}`);
      }
      assert.ok(text.includes("Pedersen"), `${file} must document Pedersen commitments`);
      assert.ok(text.includes("Policy-as-Code"), `${file} must document Policy-as-Code`);
      assert.ok(text.includes("mTLS"), `${file} must document mTLS transport boundaries`);
    }
  });
});
