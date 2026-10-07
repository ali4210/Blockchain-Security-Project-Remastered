const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");
const { spawnSync } = require("node:child_process");
const {
  word, withLocalSnapshot, captureTransaction,
} = require("./iast-trace.cjs");

const EXPECTED = {
  "package.json": "e5814463f435a5ccb4f7901c09cd3935125b8fc32bd59f094c087ca2f61506df",
  "package-lock.json": "89915039b15e0ec12a7e491ef5b9d2e2e2a4d63e669c5053c1f6cf469e548a8c",
  "requirements.txt": "ef5f065c8c5dbfe00b50fd834b5c372b278fb39fb950ed83b8f2493bbfbc7faa",
  "config/hardhat.config.js": "9f210a2ce515df82925e28642dfac959cc3f99b7ced3c3a2a23e6fd65f6a62b5",
  "contracts/solidity/VulnerableVault.sol": "31a68c972361a3e537cd9b6107eb4efb7f47b77236958098db61dbefa184354a",
};
const COMPILER_HASH = "fb03a29a517452b9f12bcf459ef37d0a543765bb3bbc911e70a87d6a37c30d5f";

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function parseArgs(args) {
  if (!Array.isArray(args) || args.length !== 1 ||
      args[0] !== "--execute-approved-local-fixture") {
    throw new Error(
      "usage: node scripts/run-iast.cjs --execute-approved-local-fixture"
    );
  }
}

function regularBytes(file, expected) {
  const info = fs.lstatSync(file);
  if (!info.isFile() || info.isSymbolicLink()) {
    throw new Error("expected a non-symlink regular input");
  }
  const bytes = fs.readFileSync(file);
  if (sha256(bytes) !== expected) throw new Error("input SHA-256 mismatch");
  return bytes;
}

function validateCompiled(output) {
  if (!output || typeof output !== "object" ||
      (output.errors !== undefined && !Array.isArray(output.errors)) ||
      (output.errors ?? []).some((item) => item.severity === "error")) {
    throw new Error("compiler output reports an error");
  }
  const contract = output.contracts?.["VulnerableVault.sol"]?.VulnerableVault;
  const runtime = contract?.evm?.deployedBytecode?.object;
  if (typeof runtime !== "string" ||
      !/^(?:[0-9a-fA-F]{2})+$/.test(runtime) || runtime.length > 49152) {
    throw new Error("invalid bounded runtime bytecode");
  }
  for (const field of ["linkReferences", "immutableReferences"]) {
    const value = contract.evm.deployedBytecode[field] ?? {};
    if (typeof value !== "object" || value === null ||
        Array.isArray(value) || Object.keys(value).length) {
      throw new Error("runtime requires unsupported linking or constructor state");
    }
  }
  const layout = contract.storageLayout;
  if (!layout || !Array.isArray(layout.storage) ||
      layout.storage.length !== 1) {
    throw new Error("unexpected fixture storage layout");
  }
  const entry = layout.storage[0];
  const type = layout.types?.[entry.type];
  if (entry.label !== "balances" || entry.slot !== "0" ||
      entry.offset !== 0 || type?.encoding !== "mapping" ||
      layout.types?.[type.key]?.label !== "address" ||
      layout.types?.[type.value]?.label !== "uint256") {
    throw new Error("unexpected balance mapping layout");
  }
  const selectors = contract.evm.methodIdentifiers;
  for (const signature of ["deposit()", "withdraw(uint256)", "balances(address)"]) {
    if (!/^[0-9a-fA-F]{8}$/.test(selectors?.[signature] ?? "")) {
      throw new Error("missing fixture method selector");
    }
  }
  return { runtime: "0x" + runtime, selectors, mappingSlot: entry.slot };
}

async function main(args) {
  parseArgs(args);
  const root = path.resolve(__dirname, "..");
  const compiler = path.join(
    os.homedir(), ".local/share/blockchain-soc/toolchains/solc-0.8.24/solc"
  );
  for (const [name, hash] of Object.entries(EXPECTED)) {
    regularBytes(path.join(root, name), hash);
  }
  regularBytes(compiler, COMPILER_HASH);

  const parent = path.join(os.homedir(), ".local/state/blockchain-soc/p03-003");
  fs.mkdirSync(parent, { recursive: true, mode: 0o700 });
  const evidence = fs.mkdtempSync(path.join(parent, "iast-"));
  fs.chmodSync(evidence, 0o700);
  const write = (name, data) => {
    const text = JSON.stringify(data, null, 2) + "\n";
    if (Buffer.byteLength(text) > 16 * 1024 * 1024) {
      throw new Error("evidence output limit exceeded");
    }
    fs.writeFileSync(path.join(evidence, name + ".json"), text, { mode: 0o600 });
  };

  try {
    const source = regularBytes(
      path.join(root, "contracts/solidity/VulnerableVault.sol"),
      EXPECTED["contracts/solidity/VulnerableVault.sol"]
    ).toString("utf8");
    const request = {
      language: "Solidity",
      sources: { "VulnerableVault.sol": { content: source } },
      settings: {
        optimizer: { enabled: false, runs: 200 },
        evmVersion: "paris",
        outputSelection: { "*": { "*": [
          "evm.deployedBytecode",
          "evm.methodIdentifiers",
          "storageLayout",
        ] } },
      },
    };
    write("compiler-input", request);
    const compiled = spawnSync(compiler, ["--standard-json"], {
      input: JSON.stringify(request),
      cwd: evidence,
      encoding: "utf8",
      timeout: 60000,
      maxBuffer: 16 * 1024 * 1024,
      env: {
        PATH: "/usr/bin:/bin",
        HOME: os.homedir(),
        LANG: "C.UTF-8",
      },
    });
    write("compiler-process", {
      exitCode: compiled.status,
      signal: compiled.signal,
      error: compiled.error?.message ?? null,
    });
    fs.writeFileSync(
      path.join(evidence, "compiler-stderr.txt"),
      compiled.stderr ?? "", { mode: 0o600 }
    );
    if (compiled.error || compiled.signal || compiled.status !== 0) {
      throw new Error("native compiler execution failed");
    }
    const output = JSON.parse(compiled.stdout);
    write("compiler-output", output);
    const build = validateCompiled(output);
    regularBytes(compiler, COMPILER_HASH);

    process.env.HARDHAT_CONFIG = path.join(root, "config/hardhat.config.js");
    process.env.HARDHAT_NETWORK = "hardhat";
    const hre = require("hardhat");
    const send = (method, params = []) => hre.network.provider.send(method, params);
    assert.equal(hre.network.name, "hardhat");
    assert.equal(hre.network.config.forking, undefined);

    const target = "0x0000000000000000000000000000000000001000";
    const records = [];
    let slot, beforeCode, beforeBalance, beforeStorage, beforeBlock;

    await withLocalSnapshot(hre, async () => {
      const [from] = await send("eth_accounts");
      assert.match(from, /^0x[0-9a-fA-F]{40}$/);
      const key = from.slice(2).padStart(64, "0");
      const mappingSlot = BigInt(build.mappingSlot).toString(16).padStart(64, "0");
      slot = await send("web3_sha3", ["0x" + key + mappingSlot]);
      assert.match(slot, /^0x[0-9a-fA-F]{64}$/);

      beforeCode = await send("eth_getCode", [target, "latest"]);
      beforeBalance = await send("eth_getBalance", [target, "latest"]);
      beforeStorage = await send("eth_getStorageAt", [target, slot, "latest"]);
      beforeBlock = await send("eth_blockNumber");
      assert.equal(beforeCode, "0x");
      assert.equal(BigInt(beforeBalance), 0n);
      assert.equal(BigInt(beforeStorage), 0n);

      await send("hardhat_setCode", [target, build.runtime]);
      const options = { scope: "approved-local-fixture", slots: [slot] };
      const base = { from, to: target, gas: "0x493e0" };

      async function capture(label, data, value, expectedOutcome, expectedValue) {
        const record = await captureTransaction(
          hre, { ...base, data, value }, options
        );
        assert.equal(record.outcome, expectedOutcome);
        assert.equal(record.stateTransitions[0].after, word(expectedValue));
        write(label, record);
        records.push({ label, ...record });
        return record;
      }

      await capture(
        "deposit-100",
        "0x" + build.selectors["deposit()"], "0x64",
        "succeeded", "64"
      );
      const withdrawal = await capture(
        "withdraw-40",
        "0x" + build.selectors["withdraw(uint256)"] + word("28").slice(2),
        "0x0", "succeeded", "3c"
      );
      const call = withdrawal.operations.find((step) => step.opcode === "CALL");
      const store = withdrawal.attemptedStorageWrites[0];
      assert.ok(call && store && call.index < store.index);
      assert.equal(BigInt(withdrawal.targetBalance.after), 60n);

      await capture(
        "reject-zero-withdraw",
        "0x" + build.selectors["withdraw(uint256)"] + word("0").slice(2),
        "0x0", "reverted-or-failed", "3c"
      );
      await capture(
        "reject-insufficient-withdraw",
        "0x" + build.selectors["withdraw(uint256)"] + word("64").slice(2),
        "0x0", "reverted-or-failed", "3c"
      );
      assert.equal(BigInt(await send("eth_getBalance", [target, "latest"])), 60n);
    });

    assert.equal(await send("eth_getCode", [target, "latest"]), beforeCode);
    assert.equal(await send("eth_getBalance", [target, "latest"]), beforeBalance);
    assert.equal(await send("eth_getStorageAt", [target, slot, "latest"]), beforeStorage);
    assert.equal(await send("eth_blockNumber"), beforeBlock);
    write("snapshot-cleanup", {
      status: "confirmed",
      codeRestored: true,
      targetBalanceRestored: true,
      selectedStorageRestored: true,
      blockNumberRestored: true,
    });

    for (const [name, hash] of Object.entries(EXPECTED)) {
      regularBytes(path.join(root, name), hash);
    }

    const summary = {
      schemaVersion: 1,
      task: "P03-003",
      status: "iast-executed",
      simulation: "disposable-in-process-hardhat",
      fixtureSha256: EXPECTED["contracts/solidity/VulnerableVault.sol"],
      compilerSha256: COMPILER_HASH,
      compilerVersion: "0.8.24",
      evmVersion: "paris",
      fixtureInstantiation: "runtime injection; constructor not executed",
      selectedMappingSlot: slot,
      cases: records.map((record) => ({
        label: record.label,
        transactionHash: record.transactionHash,
        outcome: record.outcome,
        steps: record.stepCount,
        attemptedWrites: record.attemptedStorageWrites.length,
        storageBefore: record.stateTransitions[0].before,
        storageAfter: record.stateTransitions[0].after,
      })),
      snapshotCleanup: "confirmed",
      evidenceDirectory: evidence,
      securityAcceptance: "not-established",
      taskComplete: false,
      limitations: [
        "Local simulated value only; no network deployment or real funding",
        "Root execution frame and explicitly selected storage slots only",
        "No reentrant child-contract execution or drain exploit tested",
        "Runtime insertion does not test constructor or deployment behavior",
        "Observed CALL-before-SSTORE ordering is not an exploit proof",
        "Trace limits are validated after the provider returns the trace",
        "Native compiler integration is local; existing CI runs wrapper regressions",
      ],
    };
    write("summary", summary);
    return summary;
  } catch (error) {
    write("failure", {
      status: "error",
      message: error.message,
      relatedErrors: error instanceof AggregateError
        ? error.errors.map((item) => item.message) : [],
      evidenceDirectory: evidence,
      coverage: "incomplete",
    });
    throw new Error(`${error.message}; evidence: ${evidence}`);
  }
}

module.exports = { parseArgs, validateCompiled, main, COMPILER_HASH };

if (require.main === module) {
  main(process.argv.slice(2)).then((result) => {
    process.stdout.write(JSON.stringify(result, null, 2) + "\n");
  }).catch((error) => {
    process.stderr.write(JSON.stringify({
      schemaVersion: 1, status: "error", error: error.message,
    }) + "\n");
    process.exitCode = 2;
  });
}
