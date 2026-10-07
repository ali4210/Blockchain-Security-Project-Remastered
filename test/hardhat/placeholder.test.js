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

describe("SCA dependency inventory regressions", function () {
  const {
    npmInventory, pythonInventory, pythonName,
  } = require("../../scripts/sca-inventory.cjs");

  function fixture() {
    return {
      manifest: { devDependencies: { example: "^1.0.0" } },
      lock: {
        lockfileVersion: 3,
        packages: {
          "": { devDependencies: { example: "^1.0.0" } },
          "node_modules/example": { version: "1.0.0" },
          "node_modules/parent/node_modules/example": { version: "1.0.0" },
          "node_modules/@scope/other": { version: "2.0.0", optional: true },
        },
      },
    };
  }

  it("deduplicates exact coordinates while retaining locked locations", function () {
    const { manifest, lock } = fixture();
    const inventory = npmInventory(manifest, lock);
    assert.equal(inventory.packages.length, 2);
    assert.equal(inventory.packages.find(
      (item) => item.name === "example"
    ).locations.length, 2);
    assert.ok(inventory.packages.some((item) => item.name === "@scope/other"));
    assert.equal(inventory.installedStateVerified, false);
  });

  it("retains separate versions of the same package", function () {
    const { manifest, lock } = fixture();
    lock.packages["node_modules/parent/node_modules/example"].version = "1.1.0";
    assert.equal(npmInventory(manifest, lock).packages.length, 3);
  });

  it("rejects mismatched roots, links, and non-exact versions", function () {
    let f = fixture();
    f.manifest.devDependencies.example = "^2.0.0";
    assert.throws(() => npmInventory(f.manifest, f.lock), /differ/);
    f = fixture();
    f.lock.packages["node_modules/example"].link = true;
    assert.throws(() => npmInventory(f.manifest, f.lock), /unsupported/);
    f = fixture();
    f.lock.packages["node_modules/example"].version = "^1.0.0";
    assert.throws(() => npmInventory(f.manifest, f.lock), /exact/);
  });

  it("rejects unsupported resolution sources and unsafe paths", function () {
    let f = fixture();
    f.lock.packages["node_modules/example"].resolved = "https://private.invalid/pkg";
    assert.throws(() => npmInventory(f.manifest, f.lock), /source/);
    f = fixture();
    f.lock.packages["node_modules/../escape"] = { version: "1.0.0" };
    assert.throws(() => npmInventory(f.manifest, f.lock), /unsupported/);
  });

  it("labels Python inventory as installed state rather than a lockfile", function () {
    const inventory = pythonInventory("requests\nlanggraph\n# future dependency", [
      { name: "requests", version: "2.34.2" },
      { name: "langgraph", version: "1.2.12" },
      { name: "typing_extensions", version: "4.16.0" },
    ]);
    assert.equal(inventory.packages.length, 3);
    assert.equal(inventory.declaredRoots.length, 2);
    assert.equal(inventory.reproducibleLockfile, false);
    assert.equal(inventory.freshResolutionPerformed, false);
    assert.equal(inventory.dependencyClosureProven, false);
  });

  it("canonicalizes Python names and rejects duplicate installed names", function () {
    assert.equal(pythonName("Typing_Extensions"), "typing-extensions");
    assert.throws(() => pythonInventory("requests", [
      { name: "requests", version: "2.34.2" },
      { name: "Requests", version: "2.34.2" },
    ]), /duplicate/);
  });

  it("rejects missing Python roots and unsupported requirement syntax", function () {
    assert.throws(() => pythonInventory("requests", []), /not installed/);
    assert.throws(() => pythonInventory("requests>=2", []), /unsupported/);
    assert.throws(() => pythonInventory("-r other.txt", []), /unsupported/);
    assert.throws(() => pythonInventory("# comments only", []), /empty/);
  });
});

describe("SCA lookup protocol regressions", function () {
  const { lookup, OSV_BATCH, OSV_RECORD } =
    require("../../scripts/sca-lookup.cjs");
  const packages = [{ ecosystem: "npm", name: "example", version: "1.0.0" }];
  const options = { pause: async () => {} };

  it("accepts empty matches without claiming safety or NVD coverage", async function () {
    const output = await lookup(packages, async () => ({ results: [{}] }), options);
    assert.equal(output.packages[0].advisoryIds.length, 0);
    assert.equal(output.nvdStatus, "not-queried-no-CVE-aliases");
    assert.equal(output.securityAcceptance, "not-established");
  });

  it("follows per-query pagination and deduplicates advisory IDs", async function () {
    let calls = 0;
    const request = async (url, body) => {
      if (url === OSV_BATCH) {
        calls += 1;
        if (calls === 1) return { results: [{
          vulns: [{ id: "TEST-1" }], next_page_token: "next",
        }] };
        assert.equal(body.queries[0].page_token, "next");
        return { results: [{ vulns: [{ id: "TEST-1" }, { id: "TEST-2" }] }] };
      }
      return { id: url.slice(OSV_RECORD.length), aliases: [] };
    };
    const output = await lookup(packages, request, options);
    assert.deepEqual(output.packages[0].advisoryIds, ["TEST-1", "TEST-2"]);
    assert.equal(output.advisories.length, 2);
  });

  it("rejects repeated pagination tokens", async function () {
    await assert.rejects(lookup(packages, async () => ({
      results: [{ next_page_token: "same" }],
    }), options), /repeated/);
  });

  it("rejects malformed, short, and service-error batch responses", async function () {
    for (const response of [
      { results: [] },
      { results: [{ vulns: "invalid" }] },
      { error: "unavailable" },
    ]) {
      await assert.rejects(lookup(packages, async () => response, options));
    }
  });

  it("retrieves CVE enrichment and preserves missing NVD records", async function () {
    const waits = [];
    const request = async (url) => {
      if (url === OSV_BATCH) return { results: [{ vulns: [{ id: "TEST-1" }] }] };
      if (url.startsWith(OSV_RECORD)) return {
        id: "TEST-1", aliases: ["CVE-2020-0001", "CVE-2020-0002"],
      };
      const parsed = new URL(url);
      assert.equal(parsed.searchParams.get("cveIds"), "CVE-2020-0001,CVE-2020-0002");
      return {
        startIndex: 0, totalResults: 1,
        vulnerabilities: [{ cve: { id: "CVE-2020-0001", vulnStatus: "Analyzed" } }],
      };
    };
    const output = await lookup(packages, request, {
      pause: async (ms) => waits.push(ms),
    });
    assert.deepEqual(waits, [6500]);
    assert.deepEqual(output.nvdMissingIds, ["CVE-2020-0002"]);
    assert.equal(output.nvdRecords.length, 1);
  });

  it("rejects advisory identity mismatches and unexpected NVD CVEs", async function () {
    await assert.rejects(lookup(packages, async (url) =>
      url === OSV_BATCH
        ? { results: [{ vulns: [{ id: "TEST-1" }] }] }
        : { id: "DIFFERENT" },
    options), /identity/);

    await assert.rejects(lookup(packages, async (url) => {
      if (url === OSV_BATCH) return { results: [{ vulns: [{ id: "TEST-1" }] }] };
      if (url.startsWith(OSV_RECORD)) return { id: "TEST-1", aliases: ["CVE-2020-0001"] };
      return {
        startIndex: 0, totalResults: 1,
        vulnerabilities: [{ cve: { id: "CVE-2020-9999" } }],
      };
    }, options), /unexpected/);
  });

  it("fails on network errors rather than reporting empty findings", async function () {
    await assert.rejects(lookup(packages, async () => {
      throw new Error("HTTP 403");
    }, options), /403/);
  });

  it("retains withdrawn advisories explicitly", async function () {
    const output = await lookup(packages, async (url) =>
      url === OSV_BATCH
        ? { results: [{ vulns: [{ id: "TEST-1" }] }] }
        : { id: "TEST-1", aliases: [], withdrawn: "2026-01-01T00:00:00Z" },
    options);
    assert.equal(output.advisories[0].withdrawn, "2026-01-01T00:00:00Z");
  });
});

describe("SCA transport and execution boundary regressions", function () {
  const {
    parseMode, allowedURL, makeTransport,
  } = require("../../scripts/run-sca.cjs");
  const endpoint = "https://api.osv.dev/v1/querybatch";

  it("requires an explicit supported execution mode", function () {
    assert.throws(() => parseMode([]), /usage/);
    assert.throws(() => parseMode(["--fix"]), /usage/);
    assert.equal(parseMode(["--inventory"]), "--inventory");
    assert.equal(parseMode(["--lookup-approved-public-dependencies"]),
      "--lookup-approved-public-dependencies");
  });

  it("rejects unknown hosts, credentials, and incorrect service methods", function () {
    assert.throws(() => allowedURL("http://api.osv.dev/v1/querybatch", {}), /unapproved/);
    assert.throws(() => allowedURL("https://private.invalid/query", {}), /unapproved/);
    assert.throws(() => allowedURL("https://user:secret@api.osv.dev/v1/querybatch", {}), /unapproved/);
    assert.throws(() => allowedURL(endpoint), /unapproved/);
  });

  it("uses bounded credential-free requests and caches identical queries", async function () {
    let calls = 0;
    const records = [];
    const request = makeTransport({
      fetchImpl: async (url, options) => {
        calls += 1;
        assert.equal(options.redirect, "error");
        assert.equal(options.credentials, "omit");
        assert.ok(options.signal);
        assert.equal(options.headers.Authorization, undefined);
        return new Response('{"results":[{}]}', { status: 200 });
      },
      save: (label, value) => records.push(value),
    });
    await request(endpoint, { queries: [] });
    await request(endpoint, { queries: [] });
    assert.equal(calls, 1);
    assert.equal(records.length, 1);
  });

  it("rejects HTTP errors and records failure evidence", async function () {
    const records = [];
    const request = makeTransport({
      fetchImpl: async () => new Response("blocked", { status: 403 }),
      save: (label, value) => records.push(value),
    });
    await assert.rejects(request(endpoint, {}), /HTTP 403/);
    assert.ok(records.some((item) => item.httpStatus === 403 && item.error));
  });

  it("rejects oversized bodies and malformed JSON", async function () {
    let request = makeTransport({
      maxBytes: 3,
      fetchImpl: async () => new Response("12345"),
    });
    await assert.rejects(request(endpoint, {}), /size limit/);
    request = makeTransport({
      fetchImpl: async () => new Response("not JSON"),
    });
    await assert.rejects(request(endpoint, {}));
  });

  it("rejects expired deadlines before contacting a service", async function () {
    let called = false;
    const request = makeTransport({
      now: () => 100, deadline: 99,
      fetchImpl: async () => { called = true; },
    });
    await assert.rejects(request(endpoint, {}), /deadline/);
    assert.equal(called, false);
  });

  it("propagates network failure instead of returning empty findings", async function () {
    const request = makeTransport({
      fetchImpl: async () => { throw new Error("connection failed"); },
    });
    await assert.rejects(request(endpoint, {}), /connection failed/);
  });
});

describe("SCA pagination and batch boundary regressions", function () {
  const { lookup, OSV_BATCH, OSV_RECORD } =
    require("../../scripts/sca-lookup.cjs");
  const options = { pause: async () => {} };
  const one = [{ ecosystem: "npm", name: "example", version: "1.0.0" }];

  it("keeps result identity when only one query needs another page", async function () {
    const packages = [
      { ecosystem: "npm", name: "first", version: "1.0.0" },
      { ecosystem: "PyPI", name: "second", version: "2.0.0" },
    ];
    let batches = 0;
    const result = await lookup(packages, async (url, body) => {
      if (url === OSV_BATCH) {
        batches += 1;
        if (batches === 1) return { results: [
          { vulns: [{ id: "TEST-A" }], next_page_token: "next-a" },
          { vulns: [{ id: "TEST-B" }] },
        ] };
        assert.equal(body.queries.length, 1);
        assert.equal(body.queries[0].package.name, "first");
        assert.equal(body.queries[0].page_token, "next-a");
        return { results: [{ vulns: [{ id: "TEST-A2" }] }] };
      }
      return { id: url.slice(OSV_RECORD.length), aliases: [] };
    }, options);
    assert.deepEqual(result.packages[0].advisoryIds, ["TEST-A", "TEST-A2"]);
    assert.deepEqual(result.packages[1].advisoryIds, ["TEST-B"]);
    assert.equal(batches, 2);
  });

  it("follows NVD offsets without losing CVE identity", async function () {
    const starts = [];
    const result = await lookup(one, async (url) => {
      if (url === OSV_BATCH) return {
        results: [{ vulns: [{ id: "TEST-1" }] }],
      };
      if (url.startsWith(OSV_RECORD)) return {
        id: "TEST-1", aliases: ["CVE-2020-0001", "CVE-2020-0002"],
      };
      const start = Number(new URL(url).searchParams.get("startIndex"));
      starts.push(start);
      return {
        startIndex: start,
        totalResults: 2,
        vulnerabilities: [{
          cve: { id: start === 0 ? "CVE-2020-0001" : "CVE-2020-0002" },
        }],
      };
    }, options);
    assert.deepEqual(starts, [0, 1]);
    assert.equal(result.nvdRecords.length, 2);
    assert.deepEqual(result.nvdMissingIds, []);
  });

  it("splits 101 unique CVE aliases into 100-ID and 1-ID requests", async function () {
    const aliases = Array.from({ length: 101 }, (_, index) =>
      `CVE-2020-${1000 + index}`
    );
    const sizes = [];
    const result = await lookup(one, async (url) => {
      if (url === OSV_BATCH) return {
        results: [{ vulns: [{ id: "TEST-1" }] }],
      };
      if (url.startsWith(OSV_RECORD)) return { id: "TEST-1", aliases };
      const parsed = new URL(url);
      const ids = parsed.searchParams.get("cveIds").split(",");
      sizes.push(ids.length);
      return {
        startIndex: Number(parsed.searchParams.get("startIndex")),
        totalResults: ids.length,
        vulnerabilities: ids.map((id) => ({ cve: { id } })),
      };
    }, options);
    assert.deepEqual(sizes, [100, 1]);
    assert.equal(result.nvdRequestedIds.length, 101);
    assert.equal(result.nvdRecords.length, 101);
    assert.deepEqual(result.nvdMissingIds, []);
  });

  it("rejects an empty NVD page when records remain", async function () {
    await assert.rejects(lookup(one, async (url) => {
      if (url === OSV_BATCH) return {
        results: [{ vulns: [{ id: "TEST-1" }] }],
      };
      if (url.startsWith(OSV_RECORD)) return {
        id: "TEST-1", aliases: ["CVE-2020-0001"],
      };
      return {
        startIndex: 0, totalResults: 1, vulnerabilities: [],
      };
    }, options), /progress/);
  });
});

describe("IAST state transition regressions", function () {
  const {
    word, parseTrace, withCleanup, withLocalSnapshot,
    captureTransaction, MAX_STEPS,
  } = require("../../scripts/iast-trace.cjs");

  function trace(value = "1", failed = false) {
    return {
      failed,
      structLogs: [
        { pc: 4, depth: 1, op: "SSTORE", stack: [value, "0"] },
        { pc: 5, depth: 1, op: failed ? "REVERT" : "STOP", stack: [] },
      ],
    };
  }

  it("keeps attempted writes separate from receipt outcome", function () {
    const parsed = parseTrace(trace("3", true), "0x0", ["0"]);
    assert.equal(parsed.outcome, "reverted-or-failed");
    assert.equal(parsed.attemptedStorageWrites[0].attemptedValue, word("3"));
    assert.equal(parsed.coverage.attemptedWritesAreNotCommittedState, true);
    assert.equal(parsed.stateTransitions, undefined);
  });

  it("rejects malformed, empty, oversized, and conflicting traces", function () {
    assert.throws(() => parseTrace({}, "0x1", ["0"]), /trace/);
    assert.throws(() => parseTrace(
      { failed: false, structLogs: [] }, "0x1", ["0"]
    ), /trace/);
    assert.throws(() => parseTrace(
      { failed: false, structLogs: Array(MAX_STEPS + 1).fill({}) },
      "0x1", ["0"]
    ), /trace/);
    assert.throws(() => parseTrace(trace(), "0x0", ["0"]), /conflict/);
    const malformed = trace();
    malformed.structLogs[0].stack = [];
    assert.throws(() => parseTrace(malformed, "0x1", ["0"]), /stack/);
  });

  it("rejects nested frames and unselected writes", function () {
    const nested = trace();
    nested.structLogs[0].depth = 2;
    assert.throws(() => parseTrace(nested, "0x1", ["0"]), /nested/);
    assert.throws(() => parseTrace(trace(), "0x1", ["1"]), /unselected/);
    assert.throws(() => parseTrace(trace(), "0x1", ["0", "00"]), /duplicate/);
  });

  it("requires a supported successful terminal", function () {
    const incomplete = trace();
    incomplete.structLogs.pop();
    assert.throws(() => parseTrace(incomplete, "0x1", ["0"]), /terminal/);
  });

  it("cleans up success and preserves execution failure", async function () {
    let cleaned = 0;
    assert.equal(await withCleanup(
      async () => 7, async () => { cleaned += 1; }
    ), 7);
    await assert.rejects(withCleanup(
      async () => { throw new Error("execution failed"); },
      async () => { cleaned += 1; }
    ), /execution failed/);
    assert.equal(cleaned, 2);
  });

  it("rejects cleanup failure and retains both failures", async function () {
    await assert.rejects(withCleanup(
      async () => 7,
      async () => { throw new Error("cleanup failed"); }
    ), /cleanup failed/);
    await assert.rejects(withCleanup(
      async () => { throw new Error("execution failed"); },
      async () => { throw new Error("cleanup failed"); }
    ), (error) => error instanceof AggregateError &&
      error.errors.length === 2);
  });

  it("captures real successful and reverted storage transitions", async function () {
    const hre = require("hardhat");
    const send = (method, params = []) => hre.network.provider.send(method, params);
    const target = "0x0000000000000000000000000000000000001000";
    const beforeCode = await send("eth_getCode", [target, "latest"]);

    await withLocalSnapshot(hre, async () => {
      const [from] = await send("eth_accounts");
      const transaction = {
        from, to: target, data: "0x", value: "0x0", gas: "0x186a0",
      };
      const options = { scope: "approved-local-fixture", slots: ["0"] };

      await send("hardhat_setCode", [target, "0x6001600055600260005500"]);
      await send("hardhat_setStorageAt", [target, "0x0", word("0")]);
      const success = await captureTransaction(hre, transaction, options);
      assert.equal(success.outcome, "succeeded");
      assert.equal(success.attemptedStorageWrites.length, 2);
      assert.equal(success.stateTransitions[0].before, word("0"));
      assert.equal(success.stateTransitions[0].after, word("2"));
      assert.equal(success.stateTransitions[0].changed, true);

      await send("hardhat_setCode", [target, "0x600360005560006000fd"]);
      await send("hardhat_setStorageAt", [target, "0x0", word("0")]);
      const reverted = await captureTransaction(hre, transaction, options);
      assert.equal(reverted.outcome, "reverted-or-failed");
      assert.equal(reverted.submissionThrew, true);
      assert.equal(reverted.attemptedStorageWrites[0].attemptedValue, word("3"));
      assert.equal(reverted.stateTransitions[0].after, word("0"));
      assert.equal(reverted.stateTransitions[0].changed, false);
      assert.equal(reverted.securityAcceptance, "not-established");
    });

    assert.equal(await send("eth_getCode", [target, "latest"]), beforeCode);
  });

  it("rejects execution outside an owned local snapshot", async function () {
    await assert.rejects(
      captureTransaction(require("hardhat"), {}, {}),
      /snapshot scope/
    );
    await assert.rejects(withLocalSnapshot(
      { network: { name: "localhost" } }, async () => {}
    ), /in-process/);
  });
});

describe("IAST runner boundary regressions", function () {
  const { parseArgs, validateCompiled } = require("../../scripts/run-iast.cjs");

  function output() {
    return { contracts: { "VulnerableVault.sol": { VulnerableVault: {
      evm: {
        deployedBytecode: { object: "600000" },
        methodIdentifiers: {
          "deposit()": "d0e30db0",
          "withdraw(uint256)": "2e1a7d4d",
          "balances(address)": "27e235e3",
        },
      },
      storageLayout: {
        storage: [{ label: "balances", slot: "0", offset: 0, type: "mapping" }],
        types: {
          mapping: { encoding: "mapping", key: "address", value: "uint" },
          address: { label: "address" },
          uint: { label: "uint256" },
        },
      },
    } } } };
  }

  it("requires explicit approved local execution mode", function () {
    assert.throws(() => parseArgs([]), /usage/);
    assert.throws(() => parseArgs(["--network", "mainnet"]), /usage/);
    assert.doesNotThrow(() => parseArgs(["--execute-approved-local-fixture"]));
  });

  it("accepts the supported runtime and mapping layout", function () {
    const build = validateCompiled(output());
    assert.equal(build.runtime, "0x600000");
    assert.equal(build.mappingSlot, "0");
  });

  it("rejects compiler errors and unresolved runtime requirements", function () {
    const broken = output();
    broken.errors = [{ severity: "error" }];
    assert.throws(() => validateCompiled(broken), /compiler/);
    const linked = output();
    linked.contracts["VulnerableVault.sol"].VulnerableVault
      .evm.deployedBytecode.linkReferences = { library: {} };
    assert.throws(() => validateCompiled(linked), /linking/);
    const malformed = output();
    malformed.contracts["VulnerableVault.sol"].VulnerableVault
      .evm.deployedBytecode.object = "not-bytecode";
    assert.throws(() => validateCompiled(malformed), /bytecode/);
  });

  it("rejects changed mapping layout and missing method selectors", function () {
    const changed = output();
    changed.contracts["VulnerableVault.sol"].VulnerableVault
      .storageLayout.storage[0].slot = "1";
    assert.throws(() => validateCompiled(changed), /mapping/);
    const missing = output();
    delete missing.contracts["VulnerableVault.sol"].VulnerableVault
      .evm.methodIdentifiers["withdraw(uint256)"];
    assert.throws(() => validateCompiled(missing), /selector/);
  });
});

describe("AST masking regressions", function () {
  const {
    projectAstJson, projectCompilerOutput, parseAndMask,
    MAX_SOURCE_BYTES, MAX_AST_BYTES,
  } = require("../../scripts/ast-mask-core.cjs");
  const { createHash } = require("node:crypto");
  const solc = require("solc");
  const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");

  function parsed(source) {
    return JSON.parse(solc.compile(JSON.stringify({
      language: "Solidity",
      sources: { "Input.sol": { content: source } },
      settings: {
        stopAfter: "parsing",
        outputSelection: { "*": { "": ["ast"] } },
      },
    }), { import: () => ({ error: "imports disabled" }) }));
  }

  function root() {
    return {
      nodeType: "SourceUnit",
      nodes: [{
        nodeType: "ExpressionStatement",
        expression: {
          nodeType: "Literal", kind: "string",
          hexValue: "414243", value: "ABC",
        },
      }],
    };
  }

  it("masks real ordinary, escaped, Unicode, hexadecimal and empty literals", function () {
    const output = parsed(`pragma solidity 0.8.26;
      /// @notice DOC_PAYLOAD_SENTINEL
      contract NAME_PAYLOAD_SENTINEL {
        string constant a = "ORDINARY_PAYLOAD_SENTINEL";
        string constant b = "line\\nnext";
        string constant c = unicode"বাংলা";
        bytes constant d = hex"00ff";
        string constant e = "";
      }`);
    const masked = projectCompilerOutput(output);
    assert.equal(masked.status, "masked");
    assert.equal(masked.maskedStringLiteralCount, 5);
    const text = JSON.stringify(masked);
    for (const marker of [
      "DOC_PAYLOAD_SENTINEL", "NAME_PAYLOAD_SENTINEL",
      "ORDINARY_PAYLOAD_SENTINEL", "বাংলা", "line\\nnext",
    ]) assert.equal(text.includes(marker), false);
    const hashes = masked.ast.nodes
      .filter((node) => node.literalMask)
      .map((node) => node.literalMask.sha256);
    for (const bytes of [
      Buffer.from("line\nnext"),
      Buffer.from("বাংলা"),
      Buffer.from([0, 255]),
      Buffer.alloc(0),
    ]) assert.ok(hashes.includes(hash(bytes)));
  });

  it("hashes decoded bytes rather than hexadecimal text", function () {
    const masked = projectAstJson(JSON.stringify(root()));
    const literal = masked.ast.nodes.find((node) => node.literalMask);
    assert.equal(literal.literalMask.sha256, hash(Buffer.from("ABC")));
    assert.notEqual(literal.literalMask.sha256, hash(Buffer.from("414243")));
    assert.equal(literal.literalMask.byteLength, 3);
  });

  it("omits raw names, source paths, documentation and type metadata", function () {
    const ast = root();
    ast.absolutePath = "PATH_PAYLOAD_SENTINEL";
    ast.nodes[0].name = "NAME_PAYLOAD_SENTINEL";
    ast.nodes[0].documentation = {
      nodeType: "StructuredDocumentation", text: "DOC_PAYLOAD_SENTINEL",
    };
    ast.nodes[0].expression.typeDescriptions = {
      typeString: "TYPE_PAYLOAD_SENTINEL",
    };
    const masked = projectAstJson(JSON.stringify(ast));
    assert.equal(masked.status, "masked");
    const text = JSON.stringify(masked);
    for (const marker of [
      "PATH_PAYLOAD_SENTINEL", "NAME_PAYLOAD_SENTINEL",
      "DOC_PAYLOAD_SENTINEL", "TYPE_PAYLOAD_SENTINEL", "ABC", "414243",
    ]) assert.equal(text.includes(marker), false);
  });

  it("is deterministic and does not mutate the supplied serialized AST", function () {
    const input = JSON.stringify(root());
    const first = projectAstJson(input);
    assert.deepEqual(projectAstJson(input), first);
    assert.equal(input, JSON.stringify(root()));
    assert.equal(first.ast.nodes[0].nodeType, "SourceUnit");
    assert.deepEqual(first.ast.nodes[0].children, [1]);
  });

  it("accepts the exact depth boundary and omits over-depth ASTs", function () {
    const input = JSON.stringify(root());
    assert.equal(projectAstJson(input, { maxDepth: 3 }).status, "masked");
    const excessive = projectAstJson(input, { maxDepth: 2 });
    assert.equal(excessive.status, "manual-review");
    assert.equal(excessive.reason, "depth-limit");
    assert.equal(excessive.ast, undefined);
    assert.equal(excessive.astOmitted, true);
  });

  it("routes node and output limits without returning partial projections", function () {
    const limited = projectAstJson(JSON.stringify(root()), { maxNodes: 2 });
    assert.equal(limited.reason, "node-limit");
    assert.equal(limited.ast, undefined);
    const ast = root();
    ast.nodes = Array.from({ length: 100 }, () => ({
      nodeType: "Identifier", name: "bounded",
    }));
    const output = projectAstJson(JSON.stringify(ast), { maxOutputBytes: 1024 });
    assert.equal(output.reason, "output-byte-limit");
    assert.equal(output.ast, undefined);
  });

  it("rejects malformed JSON, roots and literal encoding without echoing input", function () {
    for (const input of ["RAW_PAYLOAD_SENTINEL", "[]", '{"nodeType":null}']) {
      const masked = projectAstJson(input);
      assert.equal(masked.status, "invalid");
      assert.equal(JSON.stringify(masked).includes("RAW_PAYLOAD_SENTINEL"), false);
    }
    const ast = root();
    ast.nodes[0].expression.hexValue = "f";
    assert.equal(projectAstJson(JSON.stringify(ast)).reason, "invalid-literal");
  });

  it("routes imports, inline assembly and unknown node types to manual review", function () {
    for (const nodeType of ["ImportDirective", "InlineAssembly", "UnknownNode"]) {
      const ast = root();
      ast.nodes[0] = { nodeType };
      const masked = projectAstJson(JSON.stringify(ast));
      assert.equal(masked.status, "manual-review");
      assert.equal(masked.ast, undefined);
    }
  });

  it("rejects source errors and suppresses compiler diagnostic payloads", function () {
    const output = parsed('pragma solidity 0.8.26; contract BAD_PAYLOAD_SENTINEL {');
    const masked = projectCompilerOutput(output);
    assert.equal(masked.status, "invalid");
    assert.equal(masked.reason, "source-parse-error");
    assert.equal(JSON.stringify(masked).includes("BAD_PAYLOAD_SENTINEL"), false);
    const imported = parsed(
      'pragma solidity 0.8.26; import "IMPORT_PAYLOAD_SENTINEL.sol";'
    );
    assert.notEqual(projectCompilerOutput(imported).status, "masked");
  });

  it("rejects invalid policies and unsafe AST keys", function () {
    for (const options of [
      { maxDepth: 0 }, { maxDepth: 65 }, { maxNodes: 10001 },
      { maxOutputBytes: 1 }, { unexpected: true },
    ]) {
      assert.equal(projectAstJson(JSON.stringify(root()), options).status, "invalid");
    }
    const input = '{"nodeType":"SourceUnit","__proto__":{"payload":"SENTINEL"}}';
    assert.equal(projectAstJson(input).reason, "unsafe-ast-key");
  });

  it("checks source and AST byte limits before compiler execution", function () {
    assert.equal(
      parseAndMask("x".repeat(MAX_SOURCE_BYTES + 1)).reason,
      "source-byte-limit"
    );
    assert.equal(
      projectAstJson("x".repeat(MAX_AST_BYTES + 1)).reason,
      "ast-byte-limit"
    );
    assert.equal(parseAndMask("bad\0encoding").reason, "invalid-source-encoding");
  });

  it("requires explicit approved-fixture CLI mode", function () {
    const execution = spawnSync(process.execPath, [
      resolve(__dirname, "../../node_modules/.bin/tsx"),
      "--no-cache",
      resolve(__dirname, "../../scripts/ast-mask.mts"),
    ], { encoding: "utf8", timeout: 20000 });
    assert.equal(execution.error, undefined);
    assert.equal(execution.status, 1);
    assert.equal(execution.stderr, "");
    const masked = JSON.parse(execution.stdout);
    assert.equal(masked.reason, "explicit-approved-fixture-mode-required");
  });
});
