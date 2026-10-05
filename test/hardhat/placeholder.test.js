const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const { resolve } = require("node:path");

describe("manifest ingestion smoke test", function () {
  it("emits a valid integrity and asset-map result", function () {
    const root = resolve(__dirname, "../..");
    const result = spawnSync(
      process.execPath,
      [
        resolve(root, "node_modules/.bin/tsx"),
        "--no-cache",
        resolve(root, "scripts/ingest-manifests.mts"),
      ],
      {
        cwd: root,
        encoding: "utf8",
        timeout: 30_000,
      },
    );

    assert.equal(result.error, undefined, result.error?.message);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stderr, "");

    const output = JSON.parse(result.stdout);
    assert.equal(output.schemaVersion, 1);
    assert.equal(output.status, "valid");
    assert.ok(output.integrity);
    assert.ok(output.assetMap);
  });
});
