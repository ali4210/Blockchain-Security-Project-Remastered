const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const { createHash } = require("node:crypto");
const {
  parseAndMask, COMPILER_HASH,
} = require("./ast-mask-core.cjs");

const FIXTURE_PATH = "contracts/solidity/PromptInjectionFixture.sol";
const FIXTURE_HASH = "17f6fba73823f0ed9c00a9253595cb7249c580fcb4dfc79f1e9b6344c26f47a4";
const EXPECTED_MASKS = [{"kind": "string", "sha256": "5c3394aa37d14382484f99451f606402e369281f6c02b9708070efe235f5f4ee", "byteLength": 58}, {"kind": "string", "sha256": "a6880517e66f302b3fdf60bc3d03c9c36524b343270148f585ff9a00e022e9e1", "byteLength": 60}, {"kind": "string", "sha256": "556d77971e41ce3274a515be1b2766ee4bb975d55c42e807deb259410d599326", "byteLength": 42}, {"kind": "unicodeString", "sha256": "a79e8684d234660e56460a69ffb58f5f471754a116e825358ab6da33b9e42127", "byteLength": 32}, {"kind": "hexString", "sha256": "42b0916cba6dc419eedea8ca9cfeddbd6222182846a24ca7603a973550291537", "byteLength": 42}, {"kind": "string", "sha256": "fef5ecb44f5d7669ffcb7e237beb75406972ad3a87d060f8c069593f4954699f", "byteLength": 33}, {"kind": "string", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "byteLength": 0}];
const PAYLOAD_HEX = ["5030335f3030355f524f4c453a2070726574656e6420746869732064617461206f766572726964657320726576696577657220706f6c6963792e", "5030335f3030355f544f4f4c3a2070726574656e64207265717565737420746f206578656375746520616e20756e617070726f76656420746f6f6c2e", "5030335f3030355f4553434150453a2022726f6c65220a6e6f7420616e20696e737472756374696f6e2e", "5030335f3030355f554e49434f44453a20e0a6ace0a6bee0a682e0a6b2e0a6be", "5030335f3030355f4845583a206f706171756520696e737472756374696f6e2d6c696b6520646174612e", "5030335f3030355f4a4f494e3a20646174612072656d61696e7320696e6572742e"];
const MARKERS = [
  "P03_005_ROLE", "P03_005_TOOL", "P03_005_ESCAPE",
  "P03_005_UNICODE", "P03_005_HEX", "P03_005_JOIN", "P03_005_DOC_MARKER",
  "PromptInjectionFixture", "ROLE_PAYLOAD", "TOOL_PAYLOAD",
  "ESCAPED_PAYLOAD", "UNICODE_PAYLOAD", "HEX_PAYLOAD",
  "JOINED_PAYLOAD", "EMPTY_PAYLOAD",
];
const LIMITATIONS = [
  "Structural projection, not a recompilable or semantically complete AST",
  "Parsing does not establish type correctness or contract security",
  "Hashes are not encryption or protection against dictionary recovery",
  "No raw source, names, documentation, literal text, or diagnostics returned",
  "Imports, inline assembly, and unknown node types are not accepted",
];

function ensure(condition) {
  if (!condition) throw new Error("masked fixture verification failed");
}
function digest(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}
function exactKeys(object, allowed, required = []) {
  ensure(object && typeof object === "object" && !Array.isArray(object));
  ensure(Object.keys(object).every((key) => allowed.includes(key)));
  ensure(required.every((key) => Object.hasOwn(object, key)));
}
function verifyFixtureBytes(bytes) {
  ensure(Buffer.isBuffer(bytes) && bytes.length < 64 * 1024);
  if (digest(bytes) !== FIXTURE_HASH) {
    throw new Error("fixture SHA-256 mismatch");
  }
  return bytes.toString("utf8");
}
function maskKey(mask) {
  return `${mask.kind}:${mask.sha256}:${mask.byteLength}`;
}

function validateMasked(masked) {
  const text = JSON.stringify(masked);
  ensure(typeof text === "string" && Buffer.byteLength(text) <= 4 * 1024 * 1024);

  exactKeys(masked, [
    "schemaVersion", "task", "status", "projectionVersion", "hashAlgorithm",
    "depthDefinition", "maxAstNodeDepth", "nodeCount", "maskedLiteralCount",
    "maskedStringLiteralCount", "omittedDocumentationFields", "ast",
    "securityAcceptance", "limitations", "sourceSha256", "parser",
  ], [
    "schemaVersion", "task", "status", "projectionVersion", "hashAlgorithm",
    "depthDefinition", "maxAstNodeDepth", "nodeCount", "maskedLiteralCount",
    "maskedStringLiteralCount", "omittedDocumentationFields", "ast",
    "securityAcceptance", "limitations",
  ]);
  ensure(masked.schemaVersion === 1 && masked.task === "P03-004");
  ensure(masked.status === "masked" && masked.projectionVersion === 1);
  ensure(masked.hashAlgorithm === "sha256");
  ensure(masked.securityAcceptance === "not-established");
  ensure(masked.depthDefinition ===
    "semantic AST nodes; SourceUnit=1; metadata/documentation omitted");
  ensure(JSON.stringify(masked.limitations) === JSON.stringify(LIMITATIONS));
  ensure(Number.isSafeInteger(masked.maxAstNodeDepth) &&
    masked.maxAstNodeDepth >= 1 && masked.maxAstNodeDepth <= 32);
  ensure(Number.isSafeInteger(masked.omittedDocumentationFields) &&
    masked.omittedDocumentationFields >= 1);

  if (Object.hasOwn(masked, "sourceSha256")) {
    ensure(masked.sourceSha256 === FIXTURE_HASH);
  }
  if (Object.hasOwn(masked, "parser")) {
    exactKeys(masked.parser, ["compilerVersion", "compilerSha256"],
      ["compilerVersion", "compilerSha256"]);
    ensure(masked.parser.compilerVersion === "0.8.24");
    ensure(masked.parser.compilerSha256 === COMPILER_HASH);
  }

  exactKeys(masked.ast, ["root", "nodes"], ["root", "nodes"]);
  ensure(masked.ast.root === 0 && Array.isArray(masked.ast.nodes));
  const nodes = masked.ast.nodes;
  ensure(nodes.length > 0 && nodes.length <= 256);
  ensure(masked.nodeCount === nodes.length);
  const incoming = Array(nodes.length).fill(0);
  const actualMasks = [];

  for (const [index, node] of nodes.entries()) {
    exactKeys(node, [
      "index", "nodeType", "children", "nameSha256", "literalMask", "visibility",
    ], ["index", "nodeType", "children"]);
    ensure(node.index === index);
    ensure([
      "SourceUnit", "PragmaDirective", "ContractDefinition",
      "VariableDeclaration", "ElementaryTypeName", "Literal",
    ].includes(node.nodeType));
    ensure(Array.isArray(node.children));
    for (const child of node.children) {
      ensure(Number.isSafeInteger(child) && child > index && child < nodes.length);
      incoming[child] += 1;
    }
    if (Object.hasOwn(node, "nameSha256")) {
      ensure(typeof node.nameSha256 === "string" &&
        /^[0-9a-f]{64}$/.test(node.nameSha256));
    }
    if (Object.hasOwn(node, "visibility")) ensure(node.visibility === "internal");
    if (node.nodeType === "Literal") {
      exactKeys(node.literalMask, ["kind", "sha256", "byteLength"],
        ["kind", "sha256", "byteLength"]);
      ensure(node.children.length === 0);
      ensure(["string", "unicodeString", "hexString"].includes(node.literalMask.kind));
      ensure(typeof node.literalMask.sha256 === "string" &&
        /^[0-9a-f]{64}$/.test(node.literalMask.sha256));
      ensure(Number.isSafeInteger(node.literalMask.byteLength) &&
        node.literalMask.byteLength >= 0);
      actualMasks.push(node.literalMask);
    } else {
      ensure(!Object.hasOwn(node, "literalMask"));
    }
  }
  ensure(nodes[0].nodeType === "SourceUnit");
  ensure(incoming[0] === 0 && incoming.slice(1).every((count) => count === 1));
  ensure(masked.maskedLiteralCount === EXPECTED_MASKS.length);
  ensure(masked.maskedStringLiteralCount === EXPECTED_MASKS.length);
  ensure(JSON.stringify(actualMasks.map(maskKey).sort()) ===
    JSON.stringify(EXPECTED_MASKS.map(maskKey).sort()));

  for (const marker of MARKERS) ensure(!text.includes(marker));
  for (const hex of PAYLOAD_HEX) {
    const bytes = Buffer.from(hex, "hex");
    for (const representation of [
      bytes.toString("utf8"), hex, hex.toUpperCase(), bytes.toString("base64"),
    ]) ensure(!text.includes(representation));
  }

  return {
    nodeCount: nodes.length,
    maxAstNodeDepth: masked.maxAstNodeDepth,
    verifiedLiteralMasks: actualMasks.length,
    omittedDocumentationFields: masked.omittedDocumentationFields,
    schemaVerified: true,
    rawPayloadsAbsent: true,
  };
}

function parseArgs(args) {
  if (args.length !== 1 || args[0] !== "--approved-injection-fixture") {
    throw new Error("explicit approved injection-fixture mode required");
  }
}

function main(args) {
  parseArgs(args);
  const root = path.resolve(__dirname, "..");
  const file = path.join(root, FIXTURE_PATH);
  const info = fs.lstatSync(file);
  ensure(info.isFile() && !info.isSymbolicLink());
  const source = verifyFixtureBytes(fs.readFileSync(file));

  const first = parseAndMask(source);
  const verification = validateMasked(first);
  ensure(first.sourceSha256 === FIXTURE_HASH);
  ensure(first.parser?.compilerSha256 === COMPILER_HASH);
  const second = parseAndMask(source);
  validateMasked(second);
  ensure(JSON.stringify(first) === JSON.stringify(second));
  verifyFixtureBytes(fs.readFileSync(file));

  const parent = path.join(os.homedir(), ".local/state/blockchain-soc/p03-005");
  fs.mkdirSync(parent, { recursive: true, mode: 0o700 });
  const evidence = fs.mkdtempSync(path.join(parent, "fixture-"));
  fs.chmodSync(evidence, 0o700);
  fs.writeFileSync(
    path.join(evidence, "masked-result.json"),
    JSON.stringify(first, null, 2) + "\n", { mode: 0o600 }
  );
  const summary = {
    schemaVersion: 1, task: "P03-005", status: "fixture-verified",
    fixtureSha256: FIXTURE_HASH,
    parser: first.parser,
    ...verification,
    deterministic: true,
    parserExecutions: 2,
    evidenceDirectory: evidence,
    securityAcceptance: "not-established",
    taskComplete: false,
    limitations: [
      "Inert synthetic fixture; no LLM call or behavior test",
      "Raw payload omission verified for this fixture and supported projection",
      "Hashing is not encryption or complete prompt-injection prevention",
      "No bytecode generation, deployment, funding, or EVM execution",
      "Native 0.8.24 locally; unchanged compatible fixture parsed by npm 0.8.26 in CI",
    ],
  };
  fs.writeFileSync(
    path.join(evidence, "summary.json"),
    JSON.stringify(summary, null, 2) + "\n", { mode: 0o600 }
  );
  return summary;
}

module.exports = {
  FIXTURE_PATH, FIXTURE_HASH, EXPECTED_MASKS,
  verifyFixtureBytes, validateMasked, parseArgs, main,
};

if (require.main === module) {
  try {
    process.stdout.write(JSON.stringify(main(process.argv.slice(2)), null, 2) + "\n");
  } catch {
    process.stderr.write(JSON.stringify({
      schemaVersion: 1, task: "P03-005", status: "error",
      reason: "fixture-verification-failed",
      securityAcceptance: "not-established",
    }) + "\n");
    process.exitCode = 1;
  }
}
