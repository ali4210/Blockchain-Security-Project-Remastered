const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const { spawnSync } = require("node:child_process");
const { npmInventory, pythonInventory } = require("./sca-inventory.cjs");
const { lookup } = require("./sca-lookup.cjs");
const { verifySha256 } = require("./formal-tool-results.cjs");

const MAX_BODY = 8 * 1024 * 1024;
const EXPECTED = {
  "package.json": "e5814463f435a5ccb4f7901c09cd3935125b8fc32bd59f094c087ca2f61506df",
  "package-lock.json": "89915039b15e0ec12a7e491ef5b9d2e2e2a4d63e669c5053c1f6cf469e548a8c",
  "requirements.txt": "ef5f065c8c5dbfe00b50fd834b5c372b278fb39fb950ed83b8f2493bbfbc7faa",
};

function parseMode(args) {
  if (args.length !== 1 ||
      !["--inventory", "--lookup-approved-public-dependencies"].includes(args[0])) {
    throw new Error(
      "usage: bash scripts/run-sca.sh --inventory | " +
      "--lookup-approved-public-dependencies"
    );
  }
  return args[0];
}

function allowedURL(address, payload) {
  const url = new URL(address);
  if (url.protocol !== "https:" || url.username || url.password ||
      url.port || url.hash) throw new Error("unapproved service URL");
  if (url.hostname === "api.osv.dev") {
    if (url.pathname === "/v1/querybatch" && !url.search &&
        payload !== undefined) return url;
    if (/^\/v1\/vulns\/[A-Za-z0-9._:%-]+$/.test(url.pathname) &&
        !url.search && payload === undefined) return url;
  }
  if (url.hostname === "services.nvd.nist.gov" &&
      url.pathname === "/rest/json/cves/2.0" && payload === undefined &&
      url.searchParams.has("cveIds") &&
      [...url.searchParams.keys()].every((key) =>
        ["cveIds", "startIndex", "resultsPerPage"].includes(key)
      )) return url;
  throw new Error("unapproved service URL or method");
}

function makeTransport(options = {}) {
  const fetchImpl = options.fetchImpl ?? fetch;
  const save = options.save ?? (() => {});
  const now = options.now ?? Date.now;
  const deadline = options.deadline ?? now() + 15 * 60 * 1000;
  const maxBytes = options.maxBytes ?? MAX_BODY;
  let count = 0;
  const cache = new Map();

  return async function request(address, payload) {
    const url = allowedURL(address, payload);
    const key = JSON.stringify([url.href, payload ?? null]);
    if (cache.has(key)) return structuredClone(cache.get(key));
    const remaining = deadline - now();
    if (remaining <= 0) throw new Error("SCA lookup deadline exceeded");
    if (++count > 2500) throw new Error("SCA request limit exceeded");

    const label = `http-${String(count).padStart(4, "0")}`;
    const record = {
      url: url.href, method: payload === undefined ? "GET" : "POST",
      query: payload ?? null, startedAt: new Date().toISOString(),
    };
    try {
      const response = await fetchImpl(url.href, {
        method: record.method,
        headers: {
          "Accept": "application/json",
          "User-Agent": "Blockchain-SOC-coursework-SCA",
          ...(payload === undefined ? {} : { "Content-Type": "application/json" }),
        },
        body: payload === undefined ? undefined : JSON.stringify(payload),
        redirect: "error",
        credentials: "omit",
        signal: AbortSignal.timeout(Math.min(45000, remaining)),
      });
      record.httpStatus = response.status;
      if (!response.ok) {
        if (response.body) await response.body.cancel();
        throw new Error(`HTTP ${response.status}`);
      }
      const announced = response.headers.get("content-length");
      if (announced !== null && Number(announced) > maxBytes) {
        if (response.body) await response.body.cancel();
        throw new Error("response size limit exceeded");
      }
      if (!response.body) throw new Error("missing HTTP response body");
      const reader = response.body.getReader();
      const chunks = [];
      let bytes = 0;
      try {
        while (true) {
          const part = await reader.read();
          if (part.done) break;
          bytes += part.value.byteLength;
          if (bytes > maxBytes) {
            await reader.cancel();
            throw new Error("response size limit exceeded");
          }
          chunks.push(Buffer.from(part.value));
        }
      } finally {
        reader.releaseLock();
      }
      const data = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      record.responseBytes = bytes;
      record.response = data;
      save(label, record);
      cache.set(key, data);
      return structuredClone(data);
    } catch (error) {
      record.error = error.message;
      save(`${label}-failure`, record);
      throw new Error(`${url.hostname}: ${error.message}`);
    }
  };
}

function collectInventory(root, evidence) {
  const inputs = {};
  for (const [name, expected] of Object.entries(EXPECTED)) {
    const file = path.join(root, name);
    const info = fs.lstatSync(file);
    if (!info.isFile() || info.isSymbolicLink()) {
      throw new Error(`unexpected dependency input: ${name}`);
    }
    const bytes = fs.readFileSync(file);
    verifySha256(bytes, expected);
    inputs[name] = bytes.toString("utf8");
  }
  const npm = npmInventory(
    JSON.parse(inputs["package.json"]), JSON.parse(inputs["package-lock.json"])
  );

  const python = path.join(root, ".venv/bin/python");
  const metadataCode =
    "import importlib.metadata as m,json;" +
    "print(json.dumps([{'name':d.metadata.get('Name',''),'version':d.version}" +
    " for d in m.distributions()]))";
  const metadata = spawnSync(python, ["-I", "-c", metadataCode], {
    cwd: root, encoding: "utf8", timeout: 30000,
    maxBuffer: 8 * 1024 * 1024,
    env: { PATH: "/usr/bin:/bin", HOME: os.homedir(), LANG: "C.UTF-8" },
  });
  fs.writeFileSync(path.join(evidence, "python-metadata-stderr.txt"), metadata.stderr ?? "");
  if (metadata.error || metadata.signal || metadata.status !== 0) {
    throw new Error("project Python metadata query failed");
  }
  const distributions = JSON.parse(metadata.stdout);
  const pythonState = pythonInventory(inputs["requirements.txt"], distributions);
  return {
    schemaVersion: 1,
    inputHashes: EXPECTED,
    npm,
    python: pythonState,
    packages: [...npm.packages, ...pythonState.packages],
  };
}

async function main(args) {
  const mode = parseMode(args);
  if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === "0") {
    throw new Error("TLS verification must not be disabled");
  }
  const root = path.resolve(__dirname, "..");
  const parent = path.join(os.homedir(), ".local/state/blockchain-soc/p03-002");
  fs.mkdirSync(parent, { recursive: true, mode: 0o700 });
  const evidence = fs.mkdtempSync(path.join(parent, "sca-"));
  fs.chmodSync(evidence, 0o700);
  const write = (name, value) => fs.writeFileSync(
    path.join(evidence, `${name}.json`), JSON.stringify(value, null, 2) + "\n"
  );
  const lockFile = path.join(parent, "lookup.lock");
  let lockOwned = false;

  try {
    const inventory = collectInventory(root, evidence);
    write("inventory", inventory);
    const base = {
      schemaVersion: 1, task: "P03-002",
      npmCoordinates: inventory.npm.packages.length,
      pythonCoordinates: inventory.python.packages.length,
      pythonDeclaredRoots: inventory.python.declaredRoots,
      evidenceDirectory: evidence,
      securityAcceptance: "not-established",
      taskComplete: false,
    };
    if (mode === "--inventory") {
      const summary = { ...base, status: "inventory-only", networkLookupExecuted: false };
      write("summary", summary);
      return summary;
    }

    const fd = fs.openSync(lockFile, "wx", 0o600);
    lockOwned = true;
    try {
      fs.writeFileSync(fd, JSON.stringify({
        pid: process.pid, startedAt: new Date().toISOString(), evidenceDirectory: evidence,
      }) + "\n");
    } finally {
      fs.closeSync(fd);
    }

    const request = makeTransport({ save: write });
    const result = await lookup(inventory.packages, request);
    write("lookup", result);

    for (const [name, expected] of Object.entries(EXPECTED)) {
      verifySha256(fs.readFileSync(path.join(root, name)), expected);
    }

    const activeIds = new Set(
      result.advisories.filter((item) => item.withdrawn === null).map((item) => item.id)
    );
    const summary = {
      ...base,
      status: "lookup-completed",
      networkLookupExecuted: true,
      matchedPackageCoordinates: result.packages.filter((item) =>
        item.advisoryIds.some((id) => activeIds.has(id))
      ).length,
      uniqueAdvisories: result.advisories.length,
      activeAdvisories: activeIds.size,
      withdrawnAdvisories: result.advisories.length - activeIds.size,
      nvdStatus: result.nvdStatus,
      nvdRequestedCves: result.nvdRequestedIds.length,
      nvdReturnedCves: result.nvdRecords.length,
      nvdMissingIds: result.nvdMissingIds,
      outcome: activeIds.size ? "findings" : "no-advisories-returned-within-scope",
      limitations: [
        "npm scope includes all locked entries, not verified installed platform state",
        "Python is installed-venv inventory, not a lockfile or fresh dependency resolution",
        "Python dependency closure and declared version constraints are not proved",
        "OSV performs package/version matching; NVD enriches CVE aliases",
        "Missing NVD records and OSV advisories without CVE aliases remain visible",
        "No findings is not a comprehensive security guarantee",
        "Network responses are timestamped; future results may change",
        "Caching is per run only; service errors abort rather than use stale data",
      ],
    };
    write("summary", summary);
    return summary;
  } catch (error) {
    write("failure", {
      status: "error", error: error.message,
      coverage: "incomplete", evidenceDirectory: evidence,
    });
    throw new Error(`${error.message}; evidence: ${evidence}`);
  } finally {
    if (lockOwned) fs.unlinkSync(lockFile);
  }
}

module.exports = { parseMode, allowedURL, makeTransport, collectInventory, main };

if (require.main === module) {
  main(process.argv.slice(2)).then((summary) => {
    process.stdout.write(JSON.stringify(summary, null, 2) + "\n");
  }).catch((error) => {
    process.stderr.write(JSON.stringify({
      schemaVersion: 1, status: "error", error: error.message,
    }) + "\n");
    process.exitCode = 2;
  });
}
