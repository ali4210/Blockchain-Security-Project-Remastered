const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const { randomUUID } = require("node:crypto");
const { spawnSync } = require("node:child_process");
const {
  verifySha256, classifyScanner, classifySmt,
} = require("./formal-tool-results.cjs");

const FIXTURE_HASH = "31a68c972361a3e537cd9b6107eb4efb7f47b77236958098db61dbefa184354a";
const COMPILER_HASH = "fb03a29a517452b9f12bcf459ef37d0a543765bb3bbc911e70a87d6a37c30d5f";
const MYTHRIL_OUTER_TIMEOUT_MS = 360000;
const IMAGE = "mythril/myth@sha256:49e11758e359d0b410f648df5bbcba28a52e091a78e4772b5c02b9043666b4ff";

function parseArgs(args) {
  if (args.length !== 3 || args[0] !== "--execute-approved-fixture" ||
      args[1] !== "--z3-sha256" || !/^[0-9a-f]{64}$/.test(args[2])) {
    throw new Error(
      "usage: node scripts/run-formal-tools.cjs " +
      "--execute-approved-fixture --z3-sha256 <verified-library-sha256>"
    );
  }
  return { z3Hash: args[2] };
}

function mythrilArgs(name, bytecode) {
  if (!/^p03-001-[a-f0-9-]+$/.test(name) ||
      !/^(?:[0-9a-fA-F]{2})+$/.test(bytecode)) {
    throw new Error("invalid container name or bytecode");
  }
  return [
    "run", "--rm", "--name", name, "--pull=never",
    "--user", "mythril",
    "--network", "none", "--read-only",
    "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
    "--pids-limit", "128", "--memory", "2g", "--cpus", "1",
    "--tmpfs", "/tmp:rw,noexec,nosuid,size=128m",
    "--tmpfs", "/home/mythril/.solcx:rw,noexec,nosuid,size=64m",
    "--env", "MPLCONFIGDIR=/tmp/matplotlib",
    "--env", "MYTHRIL_DIR=/tmp/mythril",
    IMAGE, "myth", "analyze", "-c", bytecode, "--no-onchain-data",
    "--transaction-count", "3", "--max-depth", "128",
    "--execution-timeout", "120", "--solver-timeout", "10000",
    "--create-timeout", "30", "-o", "json",
  ];
}

function instrument(source, property) {
  let old, replacement;
  if (property === "deposit") {
    old = "        balances[msg.sender] += msg.value;";
    replacement =
      "        uint256 balanceBefore = balances[msg.sender];\n" +
      old + "\n" +
      "        assert(balances[msg.sender] == balanceBefore + msg.value);";
  } else if (property === "ordering") {
    old = '        (bool sent, ) = msg.sender.call{value: amount}("");';
    replacement =
      "        uint256 balanceBefore = balances[msg.sender];\n" +
      "        assert(balances[msg.sender] == balanceBefore - amount);\n" + old;
  } else {
    throw new Error("unsupported property");
  }
  if (source.split(old).length !== 2) throw new Error("instrumentation anchor mismatch");
  return source.replace(old, replacement);
}

function withContainerCleanup(operation, cleanup) {
  let value, operationError;
  try {
    value = operation();
  } catch (error) {
    operationError = error;
  }
  try {
    cleanup();
  } catch (cleanupError) {
    if (operationError) {
      throw new AggregateError(
        [operationError, cleanupError],
        "analysis and container cleanup both failed"
      );
    }
    throw cleanupError;
  }
  if (operationError) throw operationError;
  return value;
}

function assertRegular(file) {
  const info = fs.lstatSync(file);
  if (!info.isFile() || info.isSymbolicLink()) throw new Error(`not a regular file: ${file}`);
}

function main(args) {
  const options = parseArgs(args);
  const root = path.resolve(__dirname, "..");
  const home = os.homedir();
  const compiler = path.join(home, ".local/share/blockchain-soc/toolchains/solc-0.8.24/solc");
  const libraryDirectory = path.join(home, ".local/share/blockchain-soc/toolchains/z3-4.12.2");
  const library = path.join(libraryDirectory, "libz3.so");
  const alias = path.join(libraryDirectory, "libz3.so.4.12");
  const fixture = path.join(root, "contracts/solidity/VulnerableVault.sol");
  const slither = path.join(home, ".local/bin/slither");

  for (const file of [fixture, compiler, library]) assertRegular(file);
  verifySha256(fs.readFileSync(fixture), FIXTURE_HASH);
  verifySha256(fs.readFileSync(compiler), COMPILER_HASH);
  verifySha256(fs.readFileSync(library), options.z3Hash);
  if (!fs.lstatSync(alias).isSymbolicLink() || fs.readlinkSync(alias) !== "libz3.so") {
    throw new Error("unexpected isolated solver alias");
  }

  const parent = path.join(home, ".local/state/blockchain-soc/p03-001");
  fs.mkdirSync(parent, { recursive: true, mode: 0o700 });
  const evidence = fs.mkdtempSync(path.join(parent, "integrated-"));
  fs.chmodSync(evidence, 0o700);
  const env = {
    PATH: "/usr/local/bin:/usr/bin:/bin",
    HOME: home, LANG: "C.UTF-8", NO_COLOR: "1",
    LD_LIBRARY_PATH: libraryDirectory,
  };
  const source = fs.readFileSync(fixture, "utf8");
  const write = (name, value) => fs.writeFileSync(
    path.join(evidence, name), JSON.stringify(value, null, 2) + "\n"
  );

  function run(label, executable, command, timeout, input) {
    write(`${label}-command.json`, { executable, arguments: command });
    const result = spawnSync(executable, command, {
      cwd: evidence, env, encoding: "utf8", timeout,
      maxBuffer: 32 * 1024 * 1024, input,
    });
    fs.writeFileSync(path.join(evidence, `${label}-stdout.txt`), result.stdout ?? "");
    fs.writeFileSync(path.join(evidence, `${label}-stderr.txt`), result.stderr ?? "");
    write(`${label}-process.json`, {
      exitCode: result.status, signal: result.signal,
      error: result.error?.message ?? null,
    });
    if (result.error || result.signal) {
      throw new Error(`${label}: process failure: ${result.error?.message ?? result.signal}`);
    }
    return result;
  }

  function compile(label, request) {
    write(`${label}-input.json`, request);
    const result = run(label, compiler, ["--standard-json"], 120000, JSON.stringify(request));
    const output = JSON.parse(result.stdout);
    write(`${label}-output.json`, output);
    if (result.status !== 0 || (output.errors ?? []).some((item) => item.severity === "error")) {
      throw new Error(`${label}: compilation failed`);
    }
    return { result, output };
  }

  let summary;
  try {
    const metadataRun = run("image-inspect", "/usr/bin/docker",
      ["image", "inspect", IMAGE], 30000);
    if (metadataRun.status !== 0) throw new Error("pinned image unavailable; no pull attempted");
    const images = JSON.parse(metadataRun.stdout);
    if (images.length !== 1 || !images[0].RepoDigests?.includes(IMAGE) ||
        images[0].Os !== "linux" || images[0].Architecture !== "amd64") {
      throw new Error("unexpected image identity or platform");
    }

    const copiedFixture = path.join(evidence, "VulnerableVault.sol");
    fs.writeFileSync(copiedFixture, source);
    const config = path.join(evidence, "slither.config.json");
    fs.writeFileSync(config, "{}\n");
    const slitherReport = path.join(evidence, "slither-report.json");
    const staticRun = run("slither", slither, [
      copiedFixture, "--solc", compiler, "--compile-force-framework", "solc",
      "--config-file", config, "--json", slitherReport,
      "--fail-none", "--disable-color",
    ], 180000);
    const staticReport = JSON.parse(fs.readFileSync(slitherReport, "utf8"));
    const staticResult = classifyScanner("slither", staticRun.status, staticReport);
    if (staticResult.execution !== "completed") throw new Error(staticResult.reason);
    if (!staticReport.results.detectors.some((item) => item.check === "reentrancy-eth")) {
      throw new Error("expected fixture reentrancy detector result absent");
    }

    const bytecodeRequest = {
      language: "Solidity",
      sources: { "VulnerableVault.sol": { content: source } },
      settings: {
        optimizer: { enabled: false, runs: 200 }, evmVersion: "paris",
        outputSelection: { "*": { "*": ["evm.bytecode.object"] } },
      },
    };
    const compiled = compile("bytecode", bytecodeRequest);
    const bytecode = compiled.output.contracts["VulnerableVault.sol"]
      .VulnerableVault.evm.bytecode.object;
    const containerName = `p03-001-${randomUUID()}`;
    const symbolicRun = withContainerCleanup(
      () => run("mythril", "/usr/bin/docker",
        mythrilArgs(containerName, bytecode), MYTHRIL_OUTER_TIMEOUT_MS),
      () => {
        const cleanup = spawnSync("/usr/bin/docker", ["rm", "-f", containerName], {
          env, encoding: "utf8", timeout: 30000,
        });
        write("container-cleanup.json", {
          name: containerName, exitCode: cleanup.status,
          stdout: cleanup.stdout, stderr: cleanup.stderr,
          error: cleanup.error?.message ?? null,
        });
        if (cleanup.error || (cleanup.status !== 0 &&
            !(cleanup.stderr ?? "").includes("No such container"))) {
          throw new Error("container cleanup not confirmed");
        }
      }
    );
    const symbolicReport = JSON.parse(symbolicRun.stdout);
    write("mythril-report.json", symbolicReport);
    const symbolicResult = classifyScanner("mythril", symbolicRun.status, symbolicReport);
    if (symbolicResult.execution !== "completed") throw new Error(symbolicResult.reason);
    if (!symbolicReport.issues.some((item) => String(item["swc-id"]) === "107")) {
      throw new Error("expected SWC-107 fixture finding absent");
    }

    const formal = {};
    for (const [label, property, engine] of [
      ["deposit-chc", "deposit", "chc"],
      ["ordering-chc", "ordering", "chc"],
      ["ordering-bmc", "ordering", "bmc"],
    ]) {
      const text = instrument(source, property);
      const filename = `${label}.sol`;
      fs.writeFileSync(path.join(evidence, filename), text);
      const charStart = text.indexOf("assert(");
      const charEnd = text.indexOf(";", charStart) + 1;
      const target = {
        file: filename, engine,
        start: Buffer.byteLength(text.slice(0, charStart)),
        end: Buffer.byteLength(text.slice(0, charEnd)),
      };
      const modelChecker = {
        engine, solvers: ["z3"], targets: ["assert"], timeout: 10000,
        extCalls: "untrusted", showProvedSafe: true,
        showUnproved: true, showUnsupported: true,
      };
      if (engine === "bmc") modelChecker.bmcLoopIterations = 1;
      const request = {
        language: "Solidity", sources: { [filename]: { content: text } },
        settings: {
          modelChecker, outputSelection: { "*": { "*": ["abi"] } },
        },
      };
      const compiledProperty = compile(label, request);
      formal[label] = classifySmt(
        compiledProperty.result.status, compiledProperty.output, target
      );
      write(`${label}-classification.json`, formal[label]);
      if (["error", "unavailable"].includes(formal[label].status)) {
        throw new Error(`${label}: ${formal[label].reason}`);
      }
    }
    if (formal["deposit-chc"].status !== "safe") {
      throw new Error("deposit accounting proof not observed");
    }
    if (formal["ordering-bmc"].status !== "violated") {
      throw new Error("BMC function-model ordering violation not observed");
    }
    if (formal["ordering-chc"].status === "safe") {
      throw new Error("unexpected CHC ordering result; review before accepting");
    }

    summary = {
      schemaVersion: 1, task: "P03-001", status: "analysis-executed",
      fixtureSha256: FIXTURE_HASH, compilerSha256: COMPILER_HASH,
      z3LibrarySha256: options.z3Hash, mythrilImage: IMAGE,
      slither: staticResult, mythril: symbolicResult, formal,
      mythrilScope: {
        evmVersion: "paris", transactions: 3, executionSeconds: 120,
        solverTimeoutMilliseconds: 10000, outerTimeoutMilliseconds: MYTHRIL_OUTER_TIMEOUT_MS,
      },
      securityAcceptance: "not-established",
      limitations: [
        "Intentionally vulnerable local fixture; findings are retained",
        "CHC unknown remains unresolved, not a verified violation",
        "BMC ordering violation is function-level, not a drain exploit",
        "Assertions verify instrumented copies, not unchanged original bytecode",
        "Mythril analysis is bounded and uses an explicit Paris EVM build",
        "Z3 expected hash is supplied by the operator",
        "Certora credentials and proof service are not used",
      ],
      evidenceDirectory: evidence, taskComplete: false,
    };
    write("summary.json", summary);
  } catch (error) {
    write("failure.json", {
      status: "error", message: error.message, evidenceDirectory: evidence,
    });
    throw new Error(`${error.message}; evidence: ${evidence}`);
  }
  return summary;
}

module.exports = {
  parseArgs, mythrilArgs, instrument, main,
  withContainerCleanup, MYTHRIL_OUTER_TIMEOUT_MS,
};

if (require.main === module) {
  try {
    process.stdout.write(JSON.stringify(main(process.argv.slice(2)), null, 2) + "\n");
  } catch (error) {
    process.stderr.write(JSON.stringify({
      schemaVersion: 1, status: "error", error: error.message,
    }) + "\n");
    process.exitCode = 1;
  }
}
