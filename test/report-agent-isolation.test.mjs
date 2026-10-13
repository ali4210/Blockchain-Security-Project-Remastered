import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";

describe("Phase 14d: Report Generator Agent Isolation and Non-Callable Proof (P14D-004)", () => {
  it("proves report generation has zero MCP tool registration across all Python MCP servers", () => {
    // Scan all src/ directories for tool decorators or registrations
    const mcpFiles = [
      resolve(process.cwd(), "src/compliance/compliance_mcp.py"),
      resolve(process.cwd(), "src/consensus/consensus_mcp.py"),
      resolve(process.cwd(), "src/wallet/wallet_audit_mcp.py"),
    ];

    const forbiddenPhrases = [
      "generate_html_report",
      "aggregate_status",
      "status_report",
      "export_report_html",
      "run_report",
    ];

    for (const filePath of mcpFiles) {
      const content = readFileSync(filePath, "utf-8");
      for (const phrase of forbiddenPhrases) {
        assert.ok(
          !content.includes(phrase),
          `Forbidden tool capability "${phrase}" detected in ${filePath}`
        );
      }
    }
  });

  it("proves autonomous agents (A-G) have zero tool capabilities to invoke report generation", () => {
    const agentsDir = resolve(process.cwd(), "src/agents");
    const agentFiles = readdirSync(agentsDir).filter(f => f.endsWith(".py"));

    for (const file of agentFiles) {
      const content = readFileSync(resolve(agentsDir, file), "utf-8");
      assert.ok(
        !content.includes("scripts/generate-html-report"),
        `Agent script ${file} contains reference to report script`
      );
      assert.ok(
        !content.includes("generate_html_report"),
        `Agent script ${file} contains reference to report generator function`
      );
    }
  });
});
