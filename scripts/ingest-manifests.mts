import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { lstat, readdir, readFile } from "node:fs/promises";
import { relative, resolve, sep } from "node:path";

type TomlValue = string | string[];
type TomlSections = Record<string, Record<string, TomlValue>>;

type IntegrityResult = {
  files: Record<string, string>;
  lockfileVersion: number;
  toolchains: {
    foundrySolcVersion: string;
    hardhatSolidityVersion: string;
    movePackageVersion: string;
  };
};

type AssetMap = {
  schemaVersion: 1;
  contracts: {
    solidity: string[];
  };
  move: {
    manifest: "config/Move.toml";
    modules: string[];
    packages: string[];
  };
  tests: {
    foundry: string[];
    hardhat: string[];
  };
};

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
  integrity: IntegrityResult;
  assetMap: AssetMap;
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

const EXPECTED_FILE_HASHES = {
  "package.json": "e5814463f435a5ccb4f7901c09cd3935125b8fc32bd59f094c087ca2f61506df",
  "package-lock.json": "89915039b15e0ec12a7e491ef5b9d2e2e2a4d63e669c5053c1f6cf469e548a8c",
  "config/foundry.toml": "71c0b047c483a4e0c5aca70b5bc0315a75d2b3d73edd8c86e7c944a2bcb358bf",
  "config/hardhat.config.js": "9f210a2ce515df82925e28642dfac959cc3f99b7ced3c3a2a23e6fd65f6a62b5",
  "config/Move.toml": "52211ca389cb1353cd04c32ba21b2052e62fec320f7de8e4b759ddb4f6671f71",
  "contracts/solidity/PromptInjectionFixture.sol": "17f6fba73823f0ed9c00a9253595cb7249c580fcb4dfc79f1e9b6344c26f47a4",
  "contracts/solidity/VulnerableVault.sol": "31a68c972361a3e537cd9b6107eb4efb7f47b77236958098db61dbefa184354a",
} as const;

const EXPECTED_COMPILER_TOOLCHAINS = {
  foundrySolcVersion: "0.8.24",
  hardhatSolidityVersion: "0.8.24",
  movePackageVersion: "0.0.1",
} as const;

class IntegrityValidationError extends Error {
  constructor(public readonly component: string, message: string) {
    super(message);
    this.name = "IntegrityValidationError";
  }
}

function sha256(content: string | Buffer): string {
  return createHash("sha256").update(content).digest("hex");
}

async function verifyFileHashes(root: string): Promise<Record<string, string>> {
  const observed: Record<string, string> = {};

  for (const [relativePath, expected] of Object.entries(EXPECTED_FILE_HASHES)) {
    const actual = sha256(await readFile(resolve(root, relativePath)));
    if (actual !== expected) {
      throw new IntegrityValidationError(
        relativePath,
        `sha256 mismatch: expected ${expected}, received ${actual}`,
      );
    }
    observed[relativePath] = actual;
  }

  return observed;
}

async function verifyLockfile(root: string): Promise<number> {
  let lockfile: unknown;
  try {
    lockfile = JSON.parse(await readFile(resolve(root, "package-lock.json"), "utf8"));
  } catch (error) {
    throw new IntegrityValidationError(
      "package-lock.json",
      `invalid JSON: ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  if (typeof lockfile !== "object" || lockfile === null || Array.isArray(lockfile)) {
    throw new IntegrityValidationError("package-lock.json", "must be an object");
  }

  const rootLockfile = lockfile as Record<string, unknown>;
  if (rootLockfile.lockfileVersion !== 3) {
    throw new IntegrityValidationError("package-lock.json", "lockfileVersion must equal 3");
  }

  const packages = rootLockfile.packages;
  if (typeof packages !== "object" || packages === null || Array.isArray(packages)) {
    throw new IntegrityValidationError("package-lock.json", "packages must be an object");
  }

  const rootPackage = (packages as Record<string, unknown>)[""];
  if (typeof rootPackage !== "object" || rootPackage === null || Array.isArray(rootPackage)) {
    throw new IntegrityValidationError("package-lock.json", "root package entry is required");
  }

  const devDependencies = (rootPackage as Record<string, unknown>).devDependencies;
  if (typeof devDependencies !== "object" || devDependencies === null || Array.isArray(devDependencies)) {
    throw new IntegrityValidationError("package-lock.json", "root devDependencies must be an object");
  }

  const expectedDependencies = {
    hardhat: "^2.22.0",
    tsx: "^4.0.0",
    typescript: "^5.5.0",
  };

  for (const [name, expected] of Object.entries(expectedDependencies)) {
    if ((devDependencies as Record<string, unknown>)[name] !== expected) {
      throw new IntegrityValidationError(
        "package-lock.json",
        `root devDependency ${name} must equal ${expected}`,
      );
    }
  }

  for (const [path, entry] of Object.entries(packages as Record<string, unknown>)) {
    if (path === "" || typeof entry !== "object" || entry === null || Array.isArray(entry)) {
      continue;
    }
    const packageEntry = entry as Record<string, unknown>;
    const resolved = packageEntry.resolved;
    if (resolved === undefined) {
      continue;
    }
    if (typeof resolved !== "string" || !resolved.startsWith("https://registry.npmjs.org/")) {
      throw new IntegrityValidationError(
        "package-lock.json",
        `package ${path} resolved URL must use https://registry.npmjs.org/`,
      );
    }
    if (typeof packageEntry.integrity !== "string" || !packageEntry.integrity.startsWith("sha512-")) {
      throw new IntegrityValidationError(
        "package-lock.json",
        `package ${path} must declare sha512 integrity`,
      );
    }
  }

  return 3;
}

function verifyCompilerToolchains(
  manifests: IngestionResult["manifests"],
): IntegrityResult["toolchains"] {
  const observed = {
    foundrySolcVersion: manifests.foundry.solcVersion,
    hardhatSolidityVersion: manifests.hardhat.solidityVersion,
    movePackageVersion: manifests.move.package.version,
  };

  if (
    observed.foundrySolcVersion !== EXPECTED_COMPILER_TOOLCHAINS.foundrySolcVersion ||
    observed.hardhatSolidityVersion !== EXPECTED_COMPILER_TOOLCHAINS.hardhatSolidityVersion ||
    observed.movePackageVersion !== EXPECTED_COMPILER_TOOLCHAINS.movePackageVersion
  ) {
    throw new IntegrityValidationError(
      "compiler-toolchain",
      `compiler-toolchain mismatch: ${JSON.stringify(observed)}`,
    );
  }

  return observed;
}

async function verifyIntegrity(
  root: string,
  manifests: IngestionResult["manifests"],
): Promise<IntegrityResult> {
  return {
    files: await verifyFileHashes(root),
    lockfileVersion: await verifyLockfile(root),
    toolchains: verifyCompilerToolchains(manifests),
  };
}

class AssetMapValidationError extends Error {
  constructor(public readonly component: string, message: string) {
    super(message);
    this.name = "AssetMapValidationError";
  }
}

function toRelativePosixPath(root: string, path: string): string {
  const relativePath = relative(root, path);
  if (
    relativePath === "" ||
    relativePath === ".." ||
    relativePath.startsWith(`..${sep}`) ||
    relativePath.includes("\\")
  ) {
    throw new AssetMapValidationError("asset-map", `path escapes repository root: ${path}`);
  }
  return relativePath.split(sep).join("/");
}

const EXPECTED_ASSET_MAP = {
  contracts: {
    solidity: [
      "contracts/solidity/PromptInjectionFixture.sol",
      "contracts/solidity/VulnerableVault.sol",
    ],
  },
  move: {
    manifest: "config/Move.toml",
    modules: [],
    packages: [],
  },
  tests: {
    foundry: [
      "test/foundry/Exploit.t.sol",
      "test/foundry/Invariants.t.sol",
    ],
    hardhat: [
    "test/hardhat/formal-tools.test.js",
    "test/hardhat/pipeline-entrypoints.test.js",
    "test/hardhat/placeholder.test.js",
  ],
  },
} as const;

async function verifyExpectedAsset(
  root: string,
  relativePath: string,
  component: string,
): Promise<void> {
  if (
    relativePath === "" ||
    relativePath.startsWith("/") ||
    relativePath.includes("\\") ||
    relativePath.split("/").includes("..")
  ) {
    throw new AssetMapValidationError(component, `unsafe expected asset: ${relativePath}`);
  }

  const absolutePath = resolve(root, relativePath);
  if (toRelativePosixPath(root, absolutePath) !== relativePath) {
    throw new AssetMapValidationError(component, `expected asset escapes root: ${relativePath}`);
  }

  let status;
  try {
    status = await lstat(absolutePath);
  } catch (error) {
    throw new AssetMapValidationError(
      component,
      `expected asset is unavailable: ${relativePath}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  if (status.isSymbolicLink() || !status.isFile()) {
    throw new AssetMapValidationError(component, `expected asset must be a non-symlink regular file: ${relativePath}`);
  }
}

async function listVerifiedDirectoryAssets(
  root: string,
  relativeDirectory: string,
  suffix: string,
  component: string,
): Promise<string[]> {
  const directory = resolve(root, relativeDirectory);
  let status;
  try {
    status = await lstat(directory);
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") {
      return [];
    }
    throw new AssetMapValidationError(
      component,
      `cannot inspect ${relativeDirectory}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  if (status.isSymbolicLink() || !status.isDirectory()) {
    throw new AssetMapValidationError(component, `${relativeDirectory} must be a non-symlink directory`);
  }

  const assets: string[] = [];
  const visit = async (currentDirectory: string): Promise<void> => {
    const entries = await readdir(currentDirectory, { withFileTypes: true });
    entries.sort((left, right) => left.name.localeCompare(right.name));

    for (const entry of entries) {
      const currentPath = resolve(currentDirectory, entry.name);
      const relativePath = toRelativePosixPath(root, currentPath);

      if (entry.isSymbolicLink()) {
        throw new AssetMapValidationError(component, `symlink is not permitted: ${relativePath}`);
      }

      if (entry.isDirectory()) {
        await visit(currentPath);
      } else if (entry.isFile() && relativePath.endsWith(suffix)) {
        assets.push(relativePath);
      }
    }
  };

  await visit(directory);
  return assets.sort((left, right) => left.localeCompare(right));
}

async function verifyExpectedAssetList(
  root: string,
  actual: string[],
  expected: readonly string[],
  component: string,
): Promise<string[]> {
  const expectedList = [...expected].sort((left, right) => left.localeCompare(right));

  if (
    actual.length !== expectedList.length ||
    actual.some((path, index) => path !== expectedList[index])
  ) {
    throw new AssetMapValidationError(
      component,
      `asset inventory mismatch: expected ${JSON.stringify(expectedList)}, received ${JSON.stringify(actual)}`,
    );
  }

  for (const path of actual) {
    await verifyExpectedAsset(root, path, component);
  }

  return actual;
}

async function emitAssetMap(
  root: string,
  manifests: IngestionResult["manifests"],
): Promise<AssetMap> {
  const foundrySource = manifests.foundry.src;
  const hardhatSource = manifests.hardhat.paths.sources.replace(/^\.\//, "");
  if (foundrySource !== hardhatSource) {
    throw new AssetMapValidationError(
      "contracts",
      `Foundry and Hardhat source roots differ: ${foundrySource} versus ${hardhatSource}`,
    );
  }

  const foundryTest = manifests.foundry.test;
  const hardhatTest = manifests.hardhat.paths.tests.replace(/^\.\//, "");

  const solidity = await verifyExpectedAssetList(
    root,
    await listVerifiedDirectoryAssets(root, foundrySource, ".sol", "contracts"),
    EXPECTED_ASSET_MAP.contracts.solidity,
    "contracts",
  );

  const modules = await verifyExpectedAssetList(
    root,
    await listVerifiedDirectoryAssets(root, "move/modules", ".move", "move.modules"),
    EXPECTED_ASSET_MAP.move.modules,
    "move.modules",
  );

  const packages = await verifyExpectedAssetList(
    root,
    await listVerifiedDirectoryAssets(root, "move/packages", "/Move.toml", "move.packages"),
    EXPECTED_ASSET_MAP.move.packages,
    "move.packages",
  );

  const foundry = await verifyExpectedAssetList(
    root,
    await listVerifiedDirectoryAssets(root, foundryTest, ".t.sol", "tests.foundry"),
    EXPECTED_ASSET_MAP.tests.foundry,
    "tests.foundry",
  );

  const hardhat = await verifyExpectedAssetList(
    root,
    await listVerifiedDirectoryAssets(root, hardhatTest, ".test.js", "tests.hardhat"),
    EXPECTED_ASSET_MAP.tests.hardhat,
    "tests.hardhat",
  );

  await verifyExpectedAsset(root, EXPECTED_ASSET_MAP.move.manifest, "move");

  return {
    schemaVersion: 1,
    contracts: { solidity },
    move: {
      manifest: EXPECTED_ASSET_MAP.move.manifest,
      modules,
      packages,
    },
    tests: {
      foundry,
      hardhat,
    },
  };
}

export async function ingestManifests(root = process.cwd()): Promise<IngestionResult> {
  const configDir = resolve(root, "config");
  const foundry = await validateFoundry(resolve(configDir, "foundry.toml"));
  const hardhat = validateHardhat(resolve(configDir, "hardhat.config.js"));
  const move = await validateMove(resolve(configDir, "Move.toml"));

  const manifests = {
    foundry,
    hardhat,
    move,
  };

  return {
    schemaVersion: 1,
    status: "valid",
    manifests,
    integrity: await verifyIntegrity(root, manifests),
    assetMap: await emitAssetMap(root, manifests),
  };
}

async function main(): Promise<void> {
  try {
    const root = process.argv[2] ?? process.cwd();
    process.stdout.write(`${JSON.stringify(await ingestManifests(root))}\n`);
  } catch (error) {
    const result = error instanceof ManifestValidationError
      ? { schemaVersion: 1, status: "invalid", manifest: error.manifest, error: error.message }
      : error instanceof IntegrityValidationError
        ? { schemaVersion: 1, status: "invalid", component: error.component, error: error.message }
        : error instanceof AssetMapValidationError
          ? { schemaVersion: 1, status: "invalid", component: error.component, error: error.message }
          : { schemaVersion: 1, status: "error", error: error instanceof Error ? error.message : String(error) };
    process.stderr.write(`${JSON.stringify(result)}\n`);
    process.exitCode = 1;
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  void main();
}
