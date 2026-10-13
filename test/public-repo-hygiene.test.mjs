import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync, readdirSync, statSync } from "node:fs";
import { resolve, join } from "node:path";

describe("Phase 15b: Public Repository Hygiene & Policy Enforcement (P15B-005)", () => {
  it("proves tracked public files contain zero raw secrets or unredacted keys", () => {
    const forbiddenPatterns = [
      /BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY/,
      /0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d/,
    ];

    function scanDir(dir) {
      const files = readdirSync(dir);
      for (const file of files) {
        if (
          file === "node_modules" ||
          file === ".git" ||
          file === "reports" ||
          file === "cache" ||
          file === "out" ||
          file === ".backup"
        ) {
          continue;
        }
        const fullPath = join(dir, file);
        const stat = statSync(fullPath);
        if (stat.isDirectory()) {
          scanDir(fullPath);
        } else if (
          stat.isFile() &&
          (file.endsWith(".ts") ||
            file.endsWith(".mts") ||
            file.endsWith(".py") ||
            file.endsWith(".json") ||
            file.endsWith(".md"))
        ) {
          if (file.includes("public-repo-hygiene.test.mjs")) continue;
          const content = readFileSync(fullPath, "utf-8");
          for (const pattern of forbiddenPatterns) {
            assert.ok(!pattern.test(content), `Forbidden raw secret pattern detected in ${fullPath}`);
          }
        }
      }
    }

    scanDir(resolve(process.cwd(), "src"));
    scanDir(resolve(process.cwd(), "docs"));
  });

  it("verifies OPA Rego policies exist and declare valid packages", () => {
    const canonicalRegoFiles = [
      resolve(process.cwd(), "config/opa/agent_policy.rego"),
      resolve(process.cwd(), "config/opa/forensic_policy.rego"),
      resolve(process.cwd(), "policies/compliance_policy.rego"),
      resolve(process.cwd(), "policies/wallet_policy.rego"),
      resolve(process.cwd(), "policy/consensus_boundary.rego"),
    ];

    for (const f of canonicalRegoFiles) {
      assert.ok(existsSync(f), `Policy file ${f} must exist`);
      const content = readFileSync(f, "utf-8");
      assert.ok(content.includes("package "), `Policy file ${f} must declare a package`);
      assert.ok(
        /default\s+allow\s*(:=|=)\s*false/.test(content),
        `Policy file ${f} must declare fail-closed default deny`
      );
    }
  });

  it("verifies public dashboard export operates cleanly", async () => {
    const { exportPublicDashboard } = await import("../scripts/export-public-dashboard.mts");
    const outDir = exportPublicDashboard();
    assert.ok(existsSync(join(outDir, "index.html")), "Exported dashboard index.html must exist");
    assert.ok(existsSync(join(outDir, "vercel.json")), "Exported vercel.json must exist");
  });
});
