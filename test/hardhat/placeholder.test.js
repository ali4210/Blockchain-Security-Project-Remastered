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
