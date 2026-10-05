const assert = require("node:assert/strict");
const { resolve } = require("node:path");
const { spawnSync } = require("node:child_process");

describe("formal-tool policy-gate smoke test", function () {
  const root = resolve(__dirname, "../..");
  const tsx = resolve(root, "node_modules/.bin/tsx");
  const verifier = resolve(root, "scripts/verify-formal-tools.mts");

  it("reports blocked formal tools without invoking scanners or credentials", function () {
    const result = spawnSync(tsx, ["--no-cache", verifier], {
      cwd: root,
      encoding: "utf8",
      env: { ...process.env, CERTORAKEY: "" },
      timeout: 15000,
    });

    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stderr, "");

    const output = JSON.parse(result.stdout);
    assert.deepEqual(Object.keys(output.tools).sort(), ["certora", "mythril", "slither"]);
    assert.equal(output.schemaVersion, 1);
    assert.equal(output.status, "partial");
    assert.equal(output.fixture, "contracts/solidity/VulnerableVault.sol");

    for (const tool of Object.values(output.tools)) {
      assert.equal(tool.status, "blocked");
      assert.equal(typeof tool.reason, "string");
      assert.ok(tool.reason.length > 0);
    }

    assert.match(output.tools.certora.reason, /CERTORAKEY is not set/);
  });
});
