import { existsSync, readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const fixture = "contracts/solidity/VulnerableVault.sol";
const fixturePath = resolve(root, fixture);

type ToolStatus = {
  status: "blocked";
  reason: string;
};

function fail(message: string): never {
  throw new Error(message);
}

function commandExists(command: string): boolean {
  const result = spawnSync(command, ["--version"], {
    cwd: root,
    encoding: "utf8",
    env: { ...process.env, NO_COLOR: "1" },
    timeout: 5000,
  });
  return !result.error;
}

function hasLocalSolc(): boolean {
  return commandExists("solc");
}

function hasMythrilImage(): boolean {
  const result = spawnSync("docker", [
    "image", "inspect", "mythril/myth:latest",
    "--format", "{{.Id}}",
  ], {
    cwd: root,
    encoding: "utf8",
    timeout: 5000,
  });
  return result.status === 0 && (result.stdout ?? "").trim() !== "";
}

function requireFixture(): void {
  if (!existsSync(fixturePath)) {
    fail(`missing approved fixture: ${fixture}`);
  }
  const source = readFileSync(fixturePath, "utf8");
  if (!source.includes("Intentionally vulnerable local coursework fixture. Never deploy or fund.")) {
    fail(`fixture safety notice missing: ${fixture}`);
  }
}

function main(): void {
  requireFixture();

  const slither: ToolStatus = hasLocalSolc()
    ? { status: "blocked", reason: "scanner execution intentionally deferred by P03-001 policy" }
    : { status: "blocked", reason: "local solc is unavailable; no compiler download or scanner execution was attempted" };

  const mythril: ToolStatus = hasMythrilImage()
    ? { status: "blocked", reason: "scanner execution intentionally deferred by P03-001 policy" }
    : { status: "blocked", reason: "local Mythril image is unavailable; no image pull or scanner execution was attempted" };

  const certora: ToolStatus = process.env.CERTORAKEY
    ? { status: "blocked", reason: "Certora credential use is out of scope; no proof execution was attempted" }
    : { status: "blocked", reason: "CERTORAKEY is not set; no Certora proof execution was attempted" };

  process.stdout.write(`${JSON.stringify({
    schemaVersion: 1,
    status: "partial",
    fixture,
    tools: { slither, mythril, certora },
  })}\n`);
}

try {
  main();
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${JSON.stringify({
    schemaVersion: 1,
    status: "invalid",
    error: message,
  })}\n`);
  process.exitCode = 1;
}
