const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const { createHash } = require("node:crypto");
const { spawnSync } = require("node:child_process");

const COMPILER_HASH = "fb03a29a517452b9f12bcf459ef37d0a543765bb3bbc911e70a87d6a37c30d5f";
const MAX_SOURCE_BYTES = 256 * 1024;
const MAX_AST_BYTES = 8 * 1024 * 1024;
const MAX_OUTPUT_BYTES = 2 * 1024 * 1024;
const MAX_NODES = 10000;
const MAX_CONTAINERS = 100000;
const MAX_CONTAINER_DEPTH = 256;

const TYPES = new Set([
  "ArrayTypeName", "Assignment", "BinaryOperation", "Block", "Break",
  "Conditional", "Continue", "ContractDefinition", "DoWhileStatement",
  "ElementaryTypeName", "ElementaryTypeNameExpression", "EmitStatement",
  "EnumDefinition", "EnumValue", "ErrorDefinition", "EventDefinition",
  "ExpressionStatement", "ForStatement", "FunctionCall", "FunctionCallOptions",
  "FunctionDefinition", "FunctionTypeName", "Identifier", "IdentifierPath",
  "IfStatement", "IndexAccess", "IndexRangeAccess", "InheritanceSpecifier",
  "Literal", "Mapping", "MemberAccess", "ModifierDefinition",
  "ModifierInvocation", "NewExpression", "OverrideSpecifier", "ParameterList",
  "PlaceholderStatement", "PragmaDirective", "Return", "RevertStatement",
  "SourceUnit", "StructDefinition", "TryCatchClause", "TryStatement",
  "TupleExpression", "UnaryOperation", "UncheckedBlock", "UserDefinedTypeName",
  "UserDefinedValueTypeDefinition", "UsingForDirective", "VariableDeclaration",
  "VariableDeclarationStatement", "WhileStatement",
]);
const OPERATORS = new Set([
  "=", "+", "-", "*", "/", "%", "**", "!", "~", "++", "--",
  "&", "|", "^", "&&", "||", "<<", ">>",
  "+=", "-=", "*=", "/=", "%=", "<<=", ">>=", "&=", "|=", "^=",
  "==", "!=", "<", ">", "<=", ">=",
]);
const LITERAL_KINDS = new Set([
  "string", "unicodeString", "hexString", "number", "bool",
]);

function digest(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function result(status, reason) {
  return {
    schemaVersion: 1, task: "P03-004", status, reason,
    astOmitted: true, securityAcceptance: "not-established",
  };
}

function limits(options = {}) {
  if (!options || typeof options !== "object" || Array.isArray(options) ||
      Object.keys(options).some((key) =>
        !["maxDepth", "maxNodes", "maxOutputBytes"].includes(key)
      )) throw new Error("invalid-options");

  const selected = {
    maxDepth: options.maxDepth ?? 32,
    maxNodes: options.maxNodes ?? MAX_NODES,
    maxOutputBytes: options.maxOutputBytes ?? MAX_OUTPUT_BYTES,
  };
  for (const [key, min, max] of [
    ["maxDepth", 1, 64],
    ["maxNodes", 1, MAX_NODES],
    ["maxOutputBytes", 1024, MAX_OUTPUT_BYTES],
  ]) {
    if (!Number.isSafeInteger(selected[key]) ||
        selected[key] < min || selected[key] > max) {
      throw new Error("invalid-options");
    }
  }
  return selected;
}

function projectAstJson(text, options = {}) {
  let policy;
  try {
    policy = limits(options);
  } catch {
    return result("invalid", "invalid-options");
  }
  if (typeof text !== "string") return result("invalid", "invalid-ast-input");
  if (text.length > MAX_AST_BYTES || Buffer.byteLength(text) > MAX_AST_BYTES) {
    return result("manual-review", "ast-byte-limit");
  }

  let root;
  try {
    root = JSON.parse(text);
  } catch {
    return result("invalid", "invalid-ast-json");
  }
  if (!root || typeof root !== "object" || Array.isArray(root) ||
      root.nodeType !== "SourceUnit") {
    return result("invalid", "invalid-ast-root");
  }

  const nodes = [];
  let containers = 0, observedDepth = 0;
  let literalCount = 0, stringLiteralCount = 0, documentationCount = 0;
  const pending = [{ value: root, parent: null, depth: 0, containerDepth: 0 }];

  while (pending.length) {
    const item = pending.pop();
    const value = item.value;
    if (++containers > MAX_CONTAINERS ||
        item.containerDepth > MAX_CONTAINER_DEPTH) {
      return result("manual-review", "container-limit");
    }
    if (!value || typeof value !== "object") {
      return result("invalid", "invalid-ast-container");
    }

    if (Array.isArray(value)) {
      for (let index = value.length - 1; index >= 0; index--) {
        const child = value[index];
        if (child && typeof child === "object") {
          pending.push({
            ...item, value: child,
            containerDepth: item.containerDepth + 1,
          });
        }
      }
      continue;
    }

    if (["__proto__", "constructor", "prototype"].some((key) =>
      Object.hasOwn(value, key)
    )) return result("invalid", "unsafe-ast-key");

    let parent = item.parent;
    let depth = item.depth;

    if (Object.hasOwn(value, "nodeType")) {
      if (value.nodeType === "ImportDirective") {
        return result("manual-review", "imports-not-supported");
      }
      if (value.nodeType === "StructuredDocumentation") {
        documentationCount += 1;
        continue;
      }
      if (typeof value.nodeType !== "string") {
        return result("invalid", "invalid-node-type");
      }
      if (!TYPES.has(value.nodeType)) {
        return result("manual-review", "unsupported-node-type");
      }

      depth += 1;
      if (depth > policy.maxDepth) return result("manual-review", "depth-limit");
      if (nodes.length >= policy.maxNodes) {
        return result("manual-review", "node-limit");
      }
      observedDepth = Math.max(observedDepth, depth);
      const projected = {
        index: nodes.length, nodeType: value.nodeType, children: [],
      };

      if (Object.hasOwn(value, "operator")) {
        if (!OPERATORS.has(value.operator)) {
          return result("manual-review", "unsupported-operator");
        }
        projected.operator = value.operator;
      }
      for (const field of ["name", "memberName"]) {
        if (Object.hasOwn(value, field)) {
          if (typeof value[field] !== "string") {
            return result("invalid", "invalid-name-field");
          }
          projected[field + "Sha256"] = digest(Buffer.from(value[field], "utf8"));
        }
      }
      for (const [field, allowed] of [
        ["visibility", ["public", "external", "internal", "private", "default"]],
        ["stateMutability", ["payable", "nonpayable", "view", "pure"]],
      ]) {
        if (Object.hasOwn(value, field)) {
          if (!allowed.includes(value[field])) {
            return result("manual-review", "unsupported-syntax-attribute");
          }
          projected[field] = value[field];
        }
      }

      if (value.nodeType === "Literal") {
        if (!LITERAL_KINDS.has(value.kind) ||
            typeof value.hexValue !== "string" ||
            !/^(?:[0-9a-fA-F]{2})*$/.test(value.hexValue)) {
          return result("invalid", "invalid-literal");
        }
        const bytes = Buffer.from(value.hexValue, "hex");
        projected.literalMask = {
          kind: value.kind,
          sha256: digest(bytes),
          byteLength: bytes.length,
        };
        literalCount += 1;
        if (["string", "unicodeString", "hexString"].includes(value.kind)) {
          stringLiteralCount += 1;
        }
      }

      nodes.push(projected);
      if (parent !== null) nodes[parent].children.push(projected.index);
      parent = projected.index;
    }

    const keys = Object.keys(value).sort().reverse();
    for (const key of keys) {
      if (key === "documentation") {
        documentationCount += 1;
        continue;
      }
      if (key === "typeDescriptions" || key === "exportedSymbols") continue;
      const child = value[key];
      if (child && typeof child === "object") {
        pending.push({
          value: child, parent, depth,
          containerDepth: item.containerDepth + 1,
        });
      }
    }
  }

  const accepted = {
    schemaVersion: 1,
    task: "P03-004",
    status: "masked",
    projectionVersion: 1,
    hashAlgorithm: "sha256",
    depthDefinition: "semantic AST nodes; SourceUnit=1; metadata/documentation omitted",
    maxAstNodeDepth: observedDepth,
    nodeCount: nodes.length,
    maskedLiteralCount: literalCount,
    maskedStringLiteralCount: stringLiteralCount,
    omittedDocumentationFields: documentationCount,
    ast: { root: 0, nodes },
    securityAcceptance: "not-established",
    limitations: [
      "Structural projection, not a recompilable or semantically complete AST",
      "Parsing does not establish type correctness or contract security",
      "Hashes are not encryption or protection against dictionary recovery",
      "No raw source, names, documentation, literal text, or diagnostics returned",
      "Imports, inline assembly, and unknown node types are not accepted",
    ],
  };
  if (Buffer.byteLength(JSON.stringify(accepted)) > policy.maxOutputBytes) {
    return result("manual-review", "output-byte-limit");
  }
  return accepted;
}

function projectCompilerOutput(output, options = {}) {
  if (!output || typeof output !== "object" || Array.isArray(output) ||
      (output.errors !== undefined && !Array.isArray(output.errors))) {
    return result("invalid", "invalid-compiler-output");
  }
  if ((output.errors ?? []).some((item) =>
    !item || !["warning", "error", "info"].includes(item.severity)
  )) return result("invalid", "invalid-compiler-diagnostics");
  if ((output.errors ?? []).some((item) => item.severity === "error")) {
    return result("invalid", "source-parse-error");
  }
  const sources = output.sources;
  if (!sources || typeof sources !== "object" || Array.isArray(sources)) {
    return result("invalid", "missing-source-ast");
  }
  if (Object.keys(sources).length !== 1 ||
      !Object.hasOwn(sources, "Input.sol")) {
    return result("manual-review", "multi-source-not-supported");
  }
  try {
    return projectAstJson(JSON.stringify(sources["Input.sol"].ast), options);
  } catch {
    return result("invalid", "invalid-source-ast");
  }
}

function parseAndMask(source, options = {}) {
  try {
    limits(options);
  } catch {
    return result("invalid", "invalid-options");
  }
  if (typeof source !== "string") return result("invalid", "invalid-source-input");
  if (source.length > MAX_SOURCE_BYTES ||
      Buffer.byteLength(source) > MAX_SOURCE_BYTES) {
    return result("manual-review", "source-byte-limit");
  }
  if (source.includes("\0") ||
      /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(source)) {
    return result("invalid", "invalid-source-encoding");
  }

  const compiler = path.join(
    os.homedir(), ".local/share/blockchain-soc/toolchains/solc-0.8.24/solc"
  );
  try {
    const info = fs.lstatSync(compiler);
    if (!info.isFile() || info.isSymbolicLink() ||
        digest(fs.readFileSync(compiler)) !== COMPILER_HASH) {
      return result("error", "compiler-integrity-failure");
    }
  } catch {
    return result("error", "compiler-unavailable");
  }

  const request = {
    language: "Solidity",
    sources: { "Input.sol": { content: source } },
    settings: {
      stopAfter: "parsing",
      outputSelection: { "*": { "": ["ast"] } },
    },
  };
  const processResult = spawnSync(
    compiler, ["--no-import-callback", "--standard-json"], {
      input: JSON.stringify(request),
      encoding: "utf8",
      timeout: 30000,
      maxBuffer: MAX_AST_BYTES,
      cwd: path.resolve(__dirname, ".."),
      env: { PATH: "/usr/bin:/bin", HOME: os.homedir(), LANG: "C.UTF-8" },
    }
  );
  if (processResult.error || processResult.signal || processResult.status !== 0) {
    return result("error", "compiler-process-failure");
  }

  let parsed;
  try {
    parsed = JSON.parse(processResult.stdout);
  } catch {
    return result("invalid", "invalid-compiler-json");
  }
  const masked = projectCompilerOutput(parsed, options);
  return {
    ...masked,
    sourceSha256: digest(Buffer.from(source, "utf8")),
    parser: { compilerVersion: "0.8.24", compilerSha256: COMPILER_HASH },
  };
}

module.exports = {
  projectAstJson, projectCompilerOutput, parseAndMask,
  COMPILER_HASH, MAX_SOURCE_BYTES, MAX_AST_BYTES,
};
