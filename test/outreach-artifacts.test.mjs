import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";

describe("Phase 15d: Video Scripts and Outreach Artifacts (P15D-001 through P15D-004)", () => {
  const walkthroughPath = resolve(process.cwd(), "docs/WALKTHROUGH_SCRIPT.md");
  const forensicWalkthroughPath = resolve(process.cwd(), "docs/FORENSIC_WALKTHROUGH_SCRIPT.md");
  const linkedinPath = resolve(process.cwd(), "docs/OUTREACH_LINKEDIN.md");

  it("verifies 3-5 min technical walkthrough script exists with complete scenes", () => {
    assert.ok(existsSync(walkthroughPath), "docs/WALKTHROUGH_SCRIPT.md must exist");
    const content = readFileSync(walkthroughPath, "utf-8");

    assert.ok(content.includes("### Scene 1"), "Must contain Scene 1");
    assert.ok(content.includes("### Scene 2"), "Must contain Scene 2");
    assert.ok(content.includes("### Scene 3"), "Must contain Scene 3");
    assert.ok(content.includes("### Scene 4"), "Must contain Scene 4");
    assert.ok(content.includes("### Scene 5"), "Must contain Scene 5");
    assert.ok(content.includes("make deploy-soc-pipeline"), "Must reference recruiter demo target");
  });

  it("verifies 2-3 min forensic walkthrough script exists with custody invariants", () => {
    assert.ok(existsSync(forensicWalkthroughPath), "docs/FORENSIC_WALKTHROUGH_SCRIPT.md must exist");
    const content = readFileSync(forensicWalkthroughPath, "utf-8");

    assert.ok(content.includes("Order of Volatility"), "Must cover Order of Volatility");
    assert.ok(content.includes("Merkle"), "Must cover Merkle manifests");
    assert.ok(content.includes("100% fail-closed"), "Must cover 100% fail-closed integrity");
  });

  it("verifies LinkedIn outreach material embeds exact empirical benchmarks and verified repo URLs", () => {
    assert.ok(existsSync(linkedinPath), "docs/OUTREACH_LINKEDIN.md must exist");
    const content = readFileSync(linkedinPath, "utf-8");

    const requiredMetrics = ["97.4%", "84.2%", "8.4 seconds", "100% Fail-Closed"];
    for (const metric of requiredMetrics) {
      assert.ok(content.includes(metric), `LinkedIn outreach must embed exact metric: ${metric}`);
    }

    assert.ok(
      content.includes("https://github.com/ali4210/Blockchain-Security-Project-Remastered"),
      "Must reference verified GitHub repository link"
    );
  });

  it("proves outreach materials enforce zero-secret hygiene", () => {
    const forbiddenPatterns = [
      /BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY/,
      /0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d/,
    ];

    for (const file of [walkthroughPath, forensicWalkthroughPath, linkedinPath]) {
      const text = readFileSync(file, "utf-8");
      for (const pattern of forbiddenPatterns) {
        assert.ok(!pattern.test(text), `Forbidden secret pattern detected in ${file}`);
      }
    }
  });
});
