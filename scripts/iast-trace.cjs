const { createHash } = require("node:crypto");

const MAX_STEPS = 20000;
const MAX_TRACE_BYTES = 8 * 1024 * 1024;
const MAX_GAS = 300000n;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const HASH = /^0x[0-9a-fA-F]{64}$/;
let scopeActive = false;
let transactionActive = false;

function word(value) {
  if (typeof value !== "string" ||
      !/^(?:0x)?[0-9a-fA-F]{1,64}$/.test(value)) {
    throw new Error("invalid EVM word");
  }
  return "0x" + value.replace(/^0x/, "").toLowerCase().padStart(64, "0");
}

function quantity(value) {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]+$/.test(value)) {
    throw new Error("invalid RPC quantity");
  }
  return BigInt(value);
}

function parseTrace(trace, receiptStatus, selectedSlots) {
  if (!trace || typeof trace !== "object" ||
      typeof trace.failed !== "boolean" ||
      !Array.isArray(trace.structLogs) ||
      trace.structLogs.length === 0 ||
      trace.structLogs.length > MAX_STEPS) {
    throw new Error("invalid or oversized trace");
  }
  const status = quantity(receiptStatus);
  if (![0n, 1n].includes(status) || trace.failed !== (status === 0n)) {
    throw new Error("trace and receipt outcome conflict");
  }
  if (Buffer.byteLength(JSON.stringify(trace)) > MAX_TRACE_BYTES) {
    throw new Error("trace byte limit exceeded");
  }
  if (!Array.isArray(selectedSlots) || selectedSlots.length === 0 ||
      selectedSlots.length > 64) {
    throw new Error("invalid selected storage scope");
  }
  const selected = new Set(selectedSlots.map(word));
  if (selected.size !== selectedSlots.length) {
    throw new Error("duplicate selected storage slot");
  }

  const operations = [];
  const writes = [];
  for (const [index, step] of trace.structLogs.entries()) {
    if (!step || !Number.isSafeInteger(step.pc) || step.pc < 0 ||
        !Number.isSafeInteger(step.depth) ||
        typeof step.op !== "string" ||
        !/^[A-Z][A-Z0-9_]{0,31}$/.test(step.op)) {
      throw new Error("malformed trace step");
    }
    if (step.depth !== 1) {
      throw new Error("nested execution is outside supported coverage");
    }
    operations.push({ index, pc: step.pc, depth: 1, opcode: step.op });
    if (step.op === "SSTORE") {
      if (!Array.isArray(step.stack) || step.stack.length < 2 ||
          step.stack.length > 1024) {
        throw new Error("missing or malformed SSTORE stack");
      }
      const slot = word(step.stack.at(-1));
      const attemptedValue = word(step.stack.at(-2));
      if (!selected.has(slot)) {
        throw new Error("unselected storage write; coverage incomplete");
      }
      writes.push({
        index, pc: step.pc, depth: 1, slot, attemptedValue,
        stepReportedError: Boolean(step.error),
      });
    }
  }

  const last = trace.structLogs.at(-1);
  const successTerminals = ["STOP", "RETURN", "SELFDESTRUCT"];
  if (status === 1n && !successTerminals.includes(last.op)) {
    throw new Error("successful trace lacks a supported terminal");
  }
  if (status === 0n &&
      !["REVERT", "INVALID"].includes(last.op) && !last.error) {
    throw new Error("failed trace lacks a failure terminal");
  }

  return {
    outcome: status === 1n ? "succeeded" : "reverted-or-failed",
    stepCount: operations.length,
    operations,
    attemptedStorageWrites: writes,
    finalOpcode: last.op,
    coverage: {
      executionFrames: "root-only",
      storage: "explicit-selected-slots",
      nestedExecutionSupported: false,
      attemptedWritesAreNotCommittedState: true,
    },
  };
}

async function withCleanup(operation, cleanup) {
  let value, operationError, cleanupError;
  try {
    value = await operation();
  } catch (error) {
    operationError = error;
  }
  try {
    await cleanup();
  } catch (error) {
    cleanupError = error;
  }
  if (operationError && cleanupError) {
    throw new AggregateError(
      [operationError, cleanupError],
      "IAST execution and cleanup both failed"
    );
  }
  if (cleanupError) throw cleanupError;
  if (operationError) throw operationError;
  return value;
}

function requireLocal(hre) {
  if (hre !== require("hardhat") || hre.network.name !== "hardhat" ||
      hre.network.config.forking !== undefined ||
      !hre.network.provider ||
      typeof hre.network.provider.send !== "function") {
    throw new Error("only the in-process, non-forked Hardhat runtime is supported");
  }
  return (method, params = []) => hre.network.provider.send(method, params);
}

async function withLocalSnapshot(hre, operation) {
  const send = requireLocal(hre);
  if (typeof operation !== "function" || scopeActive) {
    throw new Error("invalid or overlapping IAST snapshot scope");
  }
  scopeActive = true;
  try {
    const snapshot = await send("evm_snapshot");
    return await withCleanup(operation, async () => {
      if (await send("evm_revert", [snapshot]) !== true) {
        throw new Error("IAST snapshot cleanup failed");
      }
    });
  } finally {
    scopeActive = false;
  }
}

async function captureTransaction(hre, transaction, options) {
  const send = requireLocal(hre);
  if (!scopeActive || transactionActive) {
    throw new Error("IAST requires a serial owned snapshot scope");
  }
  if (!options || options.scope !== "approved-local-fixture" ||
      !Array.isArray(options.slots) || options.slots.length === 0 ||
      options.slots.length > 64) {
    throw new Error("explicit local fixture and storage scope required");
  }
  const slots = options.slots.map(word);
  if (new Set(slots).size !== slots.length) {
    throw new Error("duplicate selected storage slot");
  }
  if (!transaction || typeof transaction !== "object" ||
      Object.keys(transaction).some((key) =>
        !["from", "to", "data", "value", "gas"].includes(key)
      ) ||
      !ADDRESS.test(transaction.from) || !ADDRESS.test(transaction.to) ||
      typeof transaction.data !== "string" ||
      !/^0x(?:[0-9a-fA-F]{2})*$/.test(transaction.data) ||
      transaction.data.length > 8194 ||
      quantity(transaction.gas) < 21000n ||
      quantity(transaction.gas) > MAX_GAS ||
      quantity(transaction.value) > 10n ** 18n) {
    throw new Error("invalid or excessive local transaction");
  }

  transactionActive = true;
  try {
    if (quantity(await send("eth_chainId")) !== 31337n) {
      throw new Error("unexpected local chain identity");
    }
    const accounts = await send("eth_accounts");
    if (!accounts.some((account) =>
      account.toLowerCase() === transaction.from.toLowerCase()
    )) throw new Error("sender is not a local test account");

    const target = transaction.to.toLowerCase();
    const code = await send("eth_getCode", [target, "latest"]);
    if (typeof code !== "string" ||
        !/^0x(?:[0-9a-fA-F]{2})+$/.test(code) ||
        code.length > 49154) {
      throw new Error("target lacks bounded local runtime code");
    }

    const beforeBlock = quantity(await send("eth_blockNumber"));
    const before = {};
    for (const slot of slots) {
      before[slot] = word(await send("eth_getStorageAt", [
        target, slot, "latest",
      ]));
    }
    const balanceBefore = await send("eth_getBalance", [target, "latest"]);

    let hash, submissionThrew = false;
    try {
      hash = await send("eth_sendTransaction", [{ ...transaction }]);
    } catch (error) {
      submissionThrew = true;
      const block = await send("eth_getBlockByNumber", ["latest", false]);
      if (!block || quantity(block.number) !== beforeBlock + 1n ||
          !Array.isArray(block.transactions) || block.transactions.length !== 1) {
        throw new Error("submission failed without uniquely attributable mined transaction");
      }
      hash = block.transactions[0];
    }
    if (!HASH.test(hash)) throw new Error("invalid transaction identity");

    const tx = await send("eth_getTransactionByHash", [hash]);
    const receipt = await send("eth_getTransactionReceipt", [hash]);
    if (!tx || !receipt ||
        tx.from?.toLowerCase() !== transaction.from.toLowerCase() ||
        tx.to?.toLowerCase() !== target ||
        tx.input?.toLowerCase() !== transaction.data.toLowerCase() ||
        quantity(tx.value) !== quantity(transaction.value) ||
        tx.hash?.toLowerCase() !== hash.toLowerCase() ||
        receipt.transactionHash?.toLowerCase() !== hash.toLowerCase() ||
        quantity(receipt.blockNumber) !== beforeBlock + 1n ||
        receipt.blockHash !== tx.blockHash) {
      throw new Error("transaction or receipt identity mismatch");
    }

    const trace = await send("debug_traceTransaction", [
      hash, { disableMemory: true, disableStack: false, disableStorage: true },
    ]);
    const parsed = parseTrace(trace, receipt.status, slots);
    if (submissionThrew && parsed.outcome === "succeeded") {
      throw new Error("submission exception conflicts with successful receipt");
    }

    const stateTransitions = [];
    for (const slot of slots) {
      const after = word(await send("eth_getStorageAt", [
        target, slot, "latest",
      ]));
      const writes = parsed.attemptedStorageWrites.filter((item) => item.slot === slot);
      const expected = parsed.outcome === "succeeded" && writes.length
        ? writes.at(-1).attemptedValue : before[slot];
      if (after !== expected) {
        throw new Error("committed storage conflicts with supported trace");
      }
      stateTransitions.push({
        slot, before: before[slot], after, changed: after !== before[slot],
      });
    }
    const balanceAfter = await send("eth_getBalance", [target, "latest"]);
    if (quantity(await send("eth_blockNumber")) !== beforeBlock + 1n) {
      throw new Error("chain advanced during capture");
    }
    if (await send("eth_getCode", [target, "latest"]) !== code) {
      throw new Error("runtime code changed during capture");
    }

    return {
      schemaVersion: 1, task: "P03-003", status: "trace-captured",
      simulation: "local-hardhat-coursework",
      transactionHash: hash, target,
      runtimeSha256: createHash("sha256")
        .update(Buffer.from(code.slice(2), "hex")).digest("hex"),
      receiptStatus: receipt.status, submissionThrew,
      ...parsed,
      stateTransitions,
      targetBalance: { before: balanceBefore, after: balanceAfter },
      securityAcceptance: "not-established",
    };
  } finally {
    transactionActive = false;
  }
}

module.exports = {
  word, parseTrace, withCleanup, withLocalSnapshot, captureTransaction,
  MAX_STEPS, MAX_TRACE_BYTES,
};
