import { createRequire } from "node:module";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

type TomlValue = string | string[];
type TomlSections = Record<string, Record<string, TomlValue>>;

export type IngestionResult = {
  schemaVersion: 1;
  status: "valid";
  manifests: {
    foundry: {
      src: string;
      test: string;
      out: string;
      libs: string[];
      solcVersion: string;
    };
    hardhat: {
      solidityVersion: string;
      optimizer: { enabled: boolean; runs: number };
      paths: {
        sources: string;
        tests: string;
        cache: string;
        artifacts: string;
      };
    };
    move: {
      package: { name: string; version: string };
      addresses: { blockchainSoc: string };
      dependencies: Record<string, never>;
    };
  };
};

export class ManifestValidationError extends Error {
  constructor(
    public readonly manifest: "foundry" | "hardhat" | "move",
    message: string,
  ) {
    super(message);
    this.name = "ManifestValidationError";
  }
}

function requireString(
  value: unknown,
  manifest: "foundry" | "hardhat" | "move",
  field: string,
): string {
  if (typeof value !== "string") {
    throw new ManifestValidationError(manifest, `${field} must be a string`);
  }
  return value;
}

function requireBoolean(
  value: unknown,
  manifest: "hardhat",
  field: string,
): boolean {
  if (typeof value !== "boolean") {
    throw new ManifestValidationError(manifest, `${field} must be a boolean`);
  }
  return value;
}

function requireNumber(
  value: unknown,
  manifest: "hardhat",
  field: string,
): number {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new ManifestValidationError(manifest, `${field} must be a finite number`);
  }
  return value;
}

function parseTomlString(raw: string, manifest: "foundry" | "move", field: string): string {
  const match = raw.match(/^"([^"]*)"$/);
  if (!match) {
    throw new ManifestValidationError(manifest, `${field} must use a quoted string`);
  }
  return match[1];
}

function parseTomlValue(raw: string, manifest: "foundry" | "move", field: string): TomlValue {
  const trimmed = raw.trim();
  if (trimmed.startsWith("[")) {
    const match = trimmed.match(/^\[\s*"([^"]*)"\s*\]$/);
    if (!match) {
      throw new ManifestValidationError(manifest, `${field} must be a single-string array`);
    }
    return [match[1]];
  }
  return parseTomlString(trimmed, manifest, field);
}

function parseSimpleToml(
  text: string,
  manifest: "foundry" | "move",
): TomlSections {
  const sections: TomlSections = {};
  let current: Record<string, TomlValue> | undefined;

  for (const [index, rawLine] of text.split(/\r?\n/).entries()) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) {
      continue;
    }

    const sectionMatch = line.match(/^\[([A-Za-z0-9_.-]+)\]$/);
    if (sectionMatch) {
      current = sections[sectionMatch[1]] ??= {};
      continue;
    }

    const keyMatch = line.match(/^([A-Za-z0-9_.-]+)\s*=\s*(.+)$/);
    if (!keyMatch || !current) {
      throw new ManifestValidationError(
        manifest,
        `unsupported TOML syntax at line ${index + 1}`,
      );
    }

    const [, key, rawValue] = keyMatch;
    if (Object.hasOwn(current, key)) {
      throw new ManifestValidationError(manifest, `duplicate key ${key}`);
    }
    current[key] = parseTomlValue(rawValue, manifest, key);
  }

  return sections;
}

function expectExact<T>(
  value: T,
  expected: T,
  manifest: "foundry" | "hardhat" | "move",
  field: string,
): T {
  if (value !== expected) {
    throw new ManifestValidationError(
      manifest,
      `${field} must equal ${JSON.stringify(expected)}`,
    );
  }
  return value;
}

function requireObject(
  value: unknown,
  manifest: "hardhat",
  field: string,
): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new ManifestValidationError(manifest, `${field} must be an object`);
  }
  return value as Record<string, unknown>;
}

async function validateFoundry(path: string): Promise<IngestionResult["manifests"]["foundry"]> {
  const sections = parseSimpleToml(await readFile(path, "utf8"), "foundry");
  const profile = sections["profile.default"];
  if (!profile) {
    throw new ManifestValidationError("foundry", "missing [profile.default]");
  }

  const src = expectExact(requireString(profile.src, "foundry", "profile.default.src"), "contracts/solidity", "foundry", "profile.default.src");
  const test = expectExact(requireString(profile.test, "foundry", "profile.default.test"), "test/foundry", "foundry", "profile.default.test");
  const out = expectExact(requireString(profile.out, "foundry", "profile.default.out"), "out", "foundry", "profile.default.out");
  const solcVersion = expectExact(requireString(profile.solc_version, "foundry", "profile.default.solc_version"), "0.8.24", "foundry", "profile.default.solc_version");
  const libs = profile.libs;

  if (!Array.isArray(libs) || libs.length !== 1 || libs[0] !== "lib") {
    throw new ManifestValidationError("foundry", "profile.default.libs must equal [\"lib\"]");
  }

  return { src, test, out, libs, solcVersion };
}

function loadHardhatConfig(path: string): Record<string, unknown> {
  const requireFromConfig = createRequire(path);
  delete requireFromConfig.cache?.[path];
  const loaded = requireFromConfig(path);
  return requireObject(loaded, "hardhat", "module.exports");
}

function validateHardhat(path: string): IngestionResult["manifests"]["hardhat"] {
  const config = loadHardhatConfig(path);
  if (Object.hasOwn(config, "networks")) {
    throw new ManifestValidationError("hardhat", "networks must be absent");
  }

  const solidity = requireObject(config.solidity, "hardhat", "solidity");
  const settings = requireObject(solidity.settings, "hardhat", "solidity.settings");
  const optimizer = requireObject(settings.optimizer, "hardhat", "solidity.settings.optimizer");
  const paths = requireObject(config.paths, "hardhat", "paths");

  const solidityVersion = expectExact(requireString(solidity.version, "hardhat", "solidity.version"), "0.8.24", "hardhat", "solidity.version");
  const enabled = expectExact(requireBoolean(optimizer.enabled, "hardhat", "solidity.settings.optimizer.enabled"), false, "hardhat", "solidity.settings.optimizer.enabled");
  const runs = expectExact(requireNumber(optimizer.runs, "hardhat", "solidity.settings.optimizer.runs"), 200, "hardhat", "solidity.settings.optimizer.runs");

  return {
    solidityVersion,
    optimizer: { enabled, runs },
    paths: {
      sources: expectExact(requireString(paths.sources, "hardhat", "paths.sources"), "./contracts/solidity", "hardhat", "paths.sources"),
      tests: expectExact(requireString(paths.tests, "hardhat", "paths.tests"), "./test/hardhat", "hardhat", "paths.tests"),
      cache: expectExact(requireString(paths.cache, "hardhat", "paths.cache"), "./cache/hardhat", "hardhat", "paths.cache"),
      artifacts: expectExact(requireString(paths.artifacts, "hardhat", "paths.artifacts"), "./artifacts/hardhat", "hardhat", "paths.artifacts"),
    },
  };
}

async function validateMove(path: string): Promise<IngestionResult["manifests"]["move"]> {
  const sections = parseSimpleToml(await readFile(path, "utf8"), "move");
  const packageSection = sections.package;
  const addresses = sections.addresses;
  const dependencies = sections.dependencies;

  if (!packageSection || !addresses || !dependencies) {
    throw new ManifestValidationError("move", "missing required package, addresses, or dependencies section");
  }

  if (Object.keys(dependencies).length !== 0) {
    throw new ManifestValidationError("move", "dependencies must be empty");
  }

  return {
    package: {
      name: expectExact(requireString(packageSection.name, "move", "package.name"), "MoveTargetPackage", "move", "package.name"),
      version: expectExact(requireString(packageSection.version, "move", "package.version"), "0.0.1", "move", "package.version"),
    },
    addresses: {
      blockchainSoc: expectExact(requireString(addresses.blockchain_soc, "move", "addresses.blockchain_soc"), "0x0", "move", "addresses.blockchain_soc"),
    },
    dependencies: {},
  };
}

export async function ingestManifests(root = process.cwd()): Promise<IngestionResult> {
  const configDir = resolve(root, "config");
  return {
    schemaVersion: 1,
    status: "valid",
    manifests: {
      foundry: await validateFoundry(resolve(configDir, "foundry.toml")),
      hardhat: validateHardhat(resolve(configDir, "hardhat.config.js")),
      move: await validateMove(resolve(configDir, "Move.toml")),
    },
  };
}

async function main(): Promise<void> {
  try {
    const root = process.argv[2] ?? process.cwd();
    process.stdout.write(`${JSON.stringify(await ingestManifests(root))}\n`);
  } catch (error) {
    const result = error instanceof ManifestValidationError
      ? { schemaVersion: 1, status: "invalid", manifest: error.manifest, error: error.message }
      : { schemaVersion: 1, status: "error", error: error instanceof Error ? error.message : String(error) };
    process.stderr.write(`${JSON.stringify(result)}\n`);
    process.exitCode = 1;
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  void main();
}
