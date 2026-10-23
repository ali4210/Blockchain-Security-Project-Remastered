const assert = require("node:assert/strict");
const { mkdtempSync, rmSync, writeFileSync } = require("node:fs");
const { tmpdir } = require("node:os");
const { resolve } = require("node:path");
const { spawnSync } = require("node:child_process");

describe("pipeline entrypoint routing smoke test", function () {
  const root = resolve(__dirname, "../..");
  const tsx = resolve(root, "node_modules/.bin/tsx");
  const verifier = resolve(root, "scripts/verify-pipeline-entrypoints.mts");

  function runFixture(fixture) {
    const directory = mkdtempSync(resolve(tmpdir(), "p02-008-"));
    const input = resolve(directory, "input.json");
    writeFileSync(input, JSON.stringify(fixture), "utf8");
    try {
      return spawnSync(tsx, ["--no-cache", verifier, input], {
        cwd: root,
        encoding: "utf8",
      });
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  }

  it("maps developer push, webhook, and on-chain stub fixtures to verify", function () {
    const fixtures = [
      { source: "developer_push", payload: { event: "push", ref: "refs/heads/main" } },
      { source: "webhook", payload: { kind: "manifest_ingestion", version: 1 } },
      { source: "on_chain_event_stub", payload: { event: "ManifestRequested", schemaVersion: 1 } },
    ];

    for (const fixture of fixtures) {
      const result = runFixture(fixture);
      assert.equal(result.status, 0, result.stderr);
      assert.equal(result.stderr, "");
      assert.deepEqual(JSON.parse(result.stdout), {
        schemaVersion: 1,
        status: "accepted",
        source: fixture.source,
        pipelineEntry: "verify",
        requiredJobs: ["runner_smoke_test", "ingest_manifests"],
      });
    }
  });

  it("rejects an unsupported webhook fixture", function () {
    const result = runFixture({
      source: "webhook",
      payload: { kind: "unsupported", version: 1 },
    });

    assert.notEqual(result.status, 0);
    assert.equal(result.stdout, "");
    const error = JSON.parse(result.stderr);
    assert.equal(error.schemaVersion, 1);
    assert.equal(error.status, "invalid");
    assert.match(error.error, /manifest_ingestion version 1/);
  });
});
