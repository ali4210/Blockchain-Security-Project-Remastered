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

describe("formal-tool result handling regressions", function () {
  const { createHash } = require("node:crypto");
  const {
    verifySha256, classifyScanner, classifySmt,
  } = require("../../scripts/formal-tool-results.cjs");

  const target = { file: "vault.sol", start: 10, end: 30, engine: "chc" };
  function diagnostic(message, overrides = {}) {
    return {
      severity: "warning",
      message,
      sourceLocation: { file: "vault.sol", start: 10, end: 30 },
      ...overrides,
    };
  }

  it("accepts matching hashes and rejects changed content", function () {
    const content = Buffer.from("approved fixture");
    const hash = createHash("sha256").update(content).digest("hex");
    assert.equal(verifySha256(content, hash), hash);
    assert.throws(() => verifySha256(Buffer.from("changed"), hash), /mismatch/);
    assert.throws(() => verifySha256(content, "invalid"), /invalid/);
  });

  it("accepts Mythril findings with exit 1 without approving security", function () {
    const result = classifyScanner("mythril", 1, {
      success: true, error: null, issues: [{ title: "State access after call" }],
    });
    assert.equal(result.execution, "completed");
    assert.equal(result.outcome, "findings");
    assert.equal(result.findingCount, 1);
    assert.equal(result.securityAcceptance, "not-established");
  });

  it("rejects Mythril success false even with exit 0", function () {
    assert.equal(classifyScanner("mythril", 0, {
      success: false, error: "read-only configuration failure", issues: [],
    }).execution, "error");
  });

  it("rejects inconsistent exits, missing exits, and malformed reports", function () {
    const report = { success: true, error: null, issues: [] };
    for (const code of [1, 2, null]) {
      assert.equal(classifyScanner("mythril", code, report).execution, "error");
    }
    assert.equal(classifyScanner("mythril", 0, {
      success: true, issues: "invalid",
    }).execution, "error");
    assert.equal(classifyScanner("mythril", 0, {
      success: true, error: "failure", issues: [],
    }).execution, "error");
  });

  it("keeps empty findings distinct from security acceptance", function () {
    const result = classifyScanner("mythril", 0, {
      success: true, error: null, issues: [],
    });
    assert.equal(result.outcome, "no-findings-within-scope");
    assert.equal(result.securityAcceptance, "not-established");
  });

  it("accepts Slither's explicitly findings-neutral execution", function () {
    const report = {
      success: true, error: null, results: { detectors: [{ check: "reentrancy-eth" }] },
    };
    assert.equal(classifyScanner("slither", 0, report).findingCount, 1);
    assert.equal(classifyScanner("slither", 1, report).execution, "error");
  });

  it("recognizes Solidity's exact safe assertion diagnostic", function () {
    const output = { errors: [
      diagnostic("CHC: Assertion violation check is safe!", { severity: "info" }),
    ] };
    assert.equal(classifySmt(0, output, target).status, "safe");
  });

  it("distinguishes definite violation from unknown", function () {
    assert.equal(classifySmt(0, { errors: [
      diagnostic("CHC: Assertion violation happens here."),
    ] }, target).status, "violated");
    assert.equal(classifySmt(0, { errors: [
      diagnostic("CHC: Assertion violation might happen here."),
    ] }, target).status, "unknown");
  });

  it("requires matching source location and engine", function () {
    const output = { errors: [
      diagnostic("CHC: Assertion violation check is safe!", {
        sourceLocation: { file: "other.sol", start: 10, end: 30 },
      }),
      diagnostic("BMC: Assertion violation happens here."),
    ] };
    assert.equal(classifySmt(0, output, target).status, "unknown");
    assert.equal(classifySmt(0, output, { ...target, engine: "bmc" }).status, "violated");
  });

  it("rejects compiler failures and identifies unavailable solvers", function () {
    assert.equal(classifySmt(0, { errors: [
      diagnostic("Solver z3 was selected but it is not available."),
    ] }, target).status, "unavailable");
    assert.equal(classifySmt(0, { errors: [
      diagnostic("Compilation failed", { severity: "error" }),
    ] }, target).status, "error");
    assert.equal(classifySmt(1, {}, target).status, "error");
  });

  it("fails closed on conflicting or malformed target results", function () {
    assert.equal(classifySmt(0, { errors: [
      diagnostic("CHC: Assertion violation check is safe!"),
      diagnostic("CHC: Assertion violation happens here."),
    ] }, target).status, "error");
    assert.equal(classifySmt(0, { errors: "invalid" }, target).status, "error");
    assert.equal(classifySmt(0, {}, { ...target, end: 0 }).status, "error");
  });
});

describe("formal-tool execution boundary regressions", function () {
  const { parseArgs, mythrilArgs, instrument } =
    require("../../scripts/run-formal-tools.cjs");

  it("requires explicit execution scope and a valid solver hash", function () {
    assert.throws(() => parseArgs([]), /usage/);
    assert.throws(() => parseArgs(["--execute-approved-fixture"]), /usage/);
    assert.throws(() => parseArgs([
      "--execute-approved-fixture", "--z3-sha256", "invalid",
    ]), /usage/);
    assert.equal(parseArgs([
      "--execute-approved-fixture", "--z3-sha256", "a".repeat(64),
    ]).z3Hash, "a".repeat(64));
  });

  it("builds digest-pinned, bounded, no-network Mythril commands", function () {
    const args = mythrilArgs("p03-001-abcd", "6000");
    for (const flag of ["--read-only", "--no-onchain-data", "--rm"]) {
      assert.ok(args.includes(flag));
    }
    for (const [flag, value] of [
      ["--network", "none"], ["--cap-drop", "ALL"],
      ["--security-opt", "no-new-privileges"], ["--pull", "never"],
      ["--user", "mythril"], ["--transaction-count", "3"],
      ["--execution-timeout", "120"],
    ]) {
      if (flag === "--pull") assert.ok(args.includes("--pull=never"));
      else assert.equal(args[args.indexOf(flag) + 1], value);
    }
    assert.ok(args.includes("MYTHRIL_DIR=/tmp/mythril"));
    for (const forbidden of ["--privileged", "--volume", "-v", "--mount"]) {
      assert.ok(!args.includes(forbidden));
    }
    assert.throws(() => mythrilArgs("unsafe name", "6000"), /invalid/);
    assert.throws(() => mythrilArgs("p03-001-abcd", "xyz"), /invalid/);
  });

  it("instruments only exact approved anchors", function () {
    const { readFileSync } = require("node:fs");
    const source = readFileSync(resolve(
      __dirname, "../../contracts/solidity/VulnerableVault.sol"
    ), "utf8");
    assert.match(instrument(source, "deposit"), /balanceBefore \+ msg.value/);
    const ordering = instrument(source, "ordering");
    assert.ok(ordering.indexOf("assert(") < ordering.indexOf("msg.sender.call"));
    assert.throws(() => instrument("unexpected source", "deposit"), /anchor/);
    assert.throws(() => instrument(source, "unsupported"), /unsupported/);
  });

  it("rejects an unapproved CLI invocation before provisioning or analysis", function () {
    const result = spawnSync(process.execPath, [
      resolve(__dirname, "../../scripts/run-formal-tools.cjs"),
    ], { encoding: "utf8", timeout: 5000 });
    assert.equal(result.status, 1);
    assert.equal(result.stdout, "");
    assert.match(JSON.parse(result.stderr).error, /usage/);
  });
});

describe("formal-tool timeout and cleanup regressions", function () {
  const {
    withContainerCleanup, mythrilArgs, MYTHRIL_OUTER_TIMEOUT_MS,
  } = require("../../scripts/run-formal-tools.cjs");

  it("attempts cleanup after a timeout and preserves the timeout error", function () {
    const timeout = Object.assign(new Error("ETIMEDOUT"), { code: "ETIMEDOUT" });
    let cleaned = 0;
    assert.throws(() => withContainerCleanup(
      () => { throw timeout; },
      () => { cleaned += 1; },
    ), (error) => error === timeout);
    assert.equal(cleaned, 1);
  });

  it("cleans up successful operations and rejects cleanup failure", function () {
    let cleaned = 0;
    assert.equal(withContainerCleanup(
      () => "result",
      () => { cleaned += 1; },
    ), "result");
    assert.equal(cleaned, 1);
    assert.throws(() => withContainerCleanup(
      () => "result",
      () => { throw new Error("cleanup failed"); },
    ), /cleanup failed/);
  });

  it("retains both errors when execution and cleanup fail", function () {
    const execution = new Error("execution failed");
    const cleanup = new Error("cleanup failed");
    assert.throws(() => withContainerCleanup(
      () => { throw execution; },
      () => { throw cleanup; },
    ), (error) =>
      error instanceof AggregateError &&
      error.errors[0] === execution &&
      error.errors[1] === cleanup
    );
  });

  it("records finite outer and per-query limits without changing transaction depth", function () {
    const args = mythrilArgs("p03-001-abcd", "6000");
    assert.equal(MYTHRIL_OUTER_TIMEOUT_MS, 360000);
    assert.equal(args[args.indexOf("--solver-timeout") + 1], "10000");
    assert.equal(args[args.indexOf("--execution-timeout") + 1], "120");
    assert.equal(args[args.indexOf("--transaction-count") + 1], "3");
    assert.equal(args[args.indexOf("--max-depth") + 1], "128");
  });
});
