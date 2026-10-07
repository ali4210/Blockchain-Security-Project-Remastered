"use strict";

const fs = require("node:fs");
const crypto = require("node:crypto");
const path = require("node:path");
const { TextDecoder } = require("node:util");

const POLICY_HASH = "7de534c7fb32284e5c0fec30aa4cc95ea13a4722d993188fe446c7fdd1c76684";
const MAX_REPORT_BYTES = 2 * 1024 * 1024;
const MAX_METADATA_BYTES = 32 * 1024;
const MAX_OUTPUT_BYTES = 256 * 1024;
const TEST_ID = /^(?:[A-Z][A-Z0-9]{2,15}-[0-9]{3,6}|LYNIS)$/;
const HASH = /^[0-9a-f]{64}$/;
const SHA = /^[0-9a-f]{40}$/;
const forbidden = new Set(["__proto__", "constructor", "prototype"]);

function invalid() {
  throw new Error("governance-input-invalid");
}

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function decode(bytes, limit) {
  if (!Buffer.isBuffer(bytes) || !bytes.length || bytes.length > limit) invalid();
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    invalid();
  }
}

function strictJson(bytes, limit) {
  const source = decode(bytes, limit);
  let position = 0;
  let nodes = 0;

  function whitespace() {
    while (position < source.length && /[ \t\r\n]/.test(source[position])) position++;
  }

  function string() {
    whitespace();
    if (source[position] !== '"') invalid();
    const start = position++;
    while (position < source.length) {
      const character = source[position++];
      if (character === "\\") {
        if (position >= source.length) invalid();
        position++;
      } else if (character === '"') {
        try {
          return JSON.parse(source.slice(start, position));
        } catch {
          invalid();
        }
      }
    }
    invalid();
  }

  function value(depth) {
    whitespace();
    if (depth > 32 || ++nodes > 20000) invalid();
    const character = source[position];

    if (character === '"') return string();

    if (character === "{") {
      position++;
      const object = Object.create(null);
      const keys = new Set();
      whitespace();
      if (source[position] === "}") {
        position++;
        return object;
      }
      while (true) {
        const key = string();
        if (key.length > 128 || forbidden.has(key) || keys.has(key)) invalid();
        keys.add(key);
        whitespace();
        if (source[position++] !== ":") invalid();
        object[key] = value(depth + 1);
        whitespace();
        const separator = source[position++];
        if (separator === "}") return object;
        if (separator !== ",") invalid();
      }
    }

    if (character === "[") {
      position++;
      const array = [];
      whitespace();
      if (source[position] === "]") {
        position++;
        return array;
      }
      while (true) {
        array.push(value(depth + 1));
        whitespace();
        const separator = source[position++];
        if (separator === "]") return array;
        if (separator !== ",") invalid();
      }
    }

    for (const [literal, result] of [
      ["true", true], ["false", false], ["null", null],
    ]) {
      if (source.startsWith(literal, position)) {
        position += literal.length;
        return result;
      }
    }

    const match = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(
      source.slice(position)
    );
    if (!match) invalid();
    position += match[0].length;
    const number = Number(match[0]);
    if (!Number.isFinite(number)) invalid();
    return number;
  }

  const result = value(0);
  whitespace();
  if (position !== source.length) invalid();
  return result;
}

function parsePolicyBytes(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length > 8192 ||
      sha256(bytes) !== POLICY_HASH) invalid();
  const policy = strictJson(bytes, 8192);
  if (policy.schemaVersion !== 1 ||
      policy.framework.officialCrosswalk !== false ||
      policy.framework.fullCatalogAssessed !== false ||
      policy.scope.productionAllowEnabled !== false ||
      policy.scope.automaticRemediation !== false ||
      policy.scope.certificationClaimAllowed !== false) invalid();
  return policy;
}

function readBounded(filename, limit) {
  let descriptor;
  try {
    descriptor = fs.openSync(
      filename, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW
    );
    const before = fs.fstatSync(descriptor);
    if (!before.isFile() || before.size <= 0 || before.size > limit) invalid();
    const buffer = Buffer.alloc(limit + 1);
    const length = fs.readSync(descriptor, buffer, 0, buffer.length, 0);
    const after = fs.fstatSync(descriptor);
    if (length !== before.size || length > limit ||
        after.size !== before.size || after.mtimeMs !== before.mtimeMs) invalid();
    return buffer.subarray(0, length);
  } catch {
    invalid();
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function readPolicyBytes() {
  return readBounded(
    path.resolve(__dirname, "../config/governance-policy.json"), 8192
  );
}

function integer(text, maximum) {
  if (!/^(?:0|[1-9]\d*)$/.test(text)) invalid();
  const result = Number(text);
  if (!Number.isSafeInteger(result) || result > maximum) invalid();
  return result;
}

function timestamp(text) {
  if (!/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(text)) invalid();
  const comparable = text.replace(" ", "T");
  const milliseconds = Date.parse(comparable + "Z");
  if (!Number.isFinite(milliseconds) ||
      new Date(milliseconds).toISOString().slice(0, 19) !== comparable) invalid();
  return text;
}

function normalize(reportBytes, metadataBytes, policyBytes) {
  const policy = parsePolicyBytes(policyBytes);
  const source = decode(reportBytes, MAX_REPORT_BYTES);
  const metadata = strictJson(metadataBytes, MAX_METADATA_BYTES);
  const reportHash = sha256(reportBytes);
  const expected = policy.provider;

  if (!metadata || Array.isArray(metadata) ||
      metadata.provider !== expected.name ||
      metadata.programVersion !== expected.programVersion ||
      metadata.packageVersion !== expected.packageVersion ||
      metadata.providerExecutableSha256 !== expected.executableSha256 ||
      metadata.profileSha256 !== expected.profileSha256 ||
      metadata.reportSha256 !== reportHash ||
      metadata.exitCode !== 0 || metadata.timedOut !== false ||
      metadata.nonRoot !== true ||
      !Number.isSafeInteger(metadata.effectiveUid) || metadata.effectiveUid <= 0 ||
      metadata.pluginsDisabled !== true ||
      metadata.uploadOptionUsed !== false ||
      metadata.remoteAuditOptionUsed !== false ||
      metadata.assessmentExecutedSuccessfully !== true ||
      !SHA.test(metadata.repositoryBaseline || "")) invalid();

  const scalarKeys = new Set([
    "lynis_version", "report_version_major", "report_version_minor",
    "report_datetime_start", "report_datetime_end",
    "lynis_tests_done", "hardening_index", "finish",
  ]);
  const scalars = new Map();
  const grouped = new Map();
  let warningRecords = 0;
  let suggestionRecords = 0;
  let continuationEligible = false;
  let continuationLines = 0;
  let omittedContinuationLines = 0;
  let omittedHyphenatedFields = 0;
  const criticalWithoutAssignment = /^(?:warning(?:\[\])?|suggestion(?:\[\])?|lynis_version|report_version_major|report_version_minor|report_datetime_start|report_datetime_end|lynis_tests_done|hardening_index|finish)(?:\s|$)/;

  const lines = source.split("\n");
  if (lines.length > 30000) invalid();

  for (const original of lines) {
    const line = original.endsWith("\r") ? original.slice(0, -1) : original;
    if (!line.trim() || line.trimStart().startsWith("#")) {
      continuationEligible = false;
      continuationLines = 0;
      continue;
    }
    if (Buffer.byteLength(line) > 256 * 1024) invalid();
    const separator = line.indexOf("=");

    if (separator < 0) {
      if (!continuationEligible || Buffer.byteLength(line) > 4096 ||
          criticalWithoutAssignment.test(line.trimStart()) ||
          ++continuationLines > 8 || ++omittedContinuationLines > 256) invalid();
      continue;
    }
    if (separator === 0) invalid();

    continuationEligible = false;
    continuationLines = 0;
    const key = line.slice(0, separator);
    const rawValue = line.slice(separator + 1);
    if (forbidden.has(key) ||
        !/^[a-z][a-z0-9_-]*(?:\[\])?$/.test(key) ||
        key === "warning" || key === "suggestion" ||
        (key.includes("-") && scalarKeys.has(key.replaceAll("-", "_")))) invalid();
    if (key.includes("-")) omittedHyphenatedFields++;

    if (scalarKeys.has(key)) {
      if (scalars.has(key)) invalid();
      scalars.set(key, rawValue.trim());
    } else if (key === "warning[]" || key === "suggestion[]") {
      const testId = rawValue.split("|", 1)[0].trim();
      if (!TEST_ID.test(testId)) invalid();
      continuationEligible = true;
      const kind = key === "warning[]" ? "warning" : "suggestion";
      if (kind === "warning") warningRecords++;
      else suggestionRecords++;
      if (warningRecords + suggestionRecords > 1024) invalid();
      const groupKey = kind + ":" + testId;
      const existing = grouped.get(groupKey);
      if (existing) existing.occurrences++;
      else grouped.set(groupKey, { kind, testId, occurrences: 1 });
      if (grouped.size > 512) invalid();
    }
    // All other host data and all finding descriptions are intentionally omitted.
  }

  for (const key of scalarKeys) {
    if (!scalars.has(key)) invalid();
  }
  if (scalars.get("lynis_version") !== expected.programVersion ||
      scalars.get("report_version_major") !== "1" ||
      scalars.get("report_version_minor") !== "0" ||
      !scalars.get("finish") || scalars.get("finish").length > 16) invalid();

  const started = timestamp(scalars.get("report_datetime_start"));
  const ended = timestamp(scalars.get("report_datetime_end"));
  if (ended < started) invalid();

  const hardeningIndex = integer(scalars.get("hardening_index"), 100);
  const testsDone = integer(scalars.get("lynis_tests_done"), 100000);
  const mapping = new Map(policy.mappings.map(item => [item.testId, item]));

  const findings = [...grouped.values()].sort((left, right) => {
    const a = left.kind + ":" + left.testId;
    const b = right.kind + ":" + right.testId;
    return a < b ? -1 : a > b ? 1 : 0;
  }).map(item => ({
    ...item,
    relatedNistControls: mapping.has(item.testId)
      ? [mapping.get(item.testId).controlId] : [],
  }));

  const mappedRecords = findings.reduce(
    (sum, item) => sum + (item.relatedNistControls.length ? item.occurrences : 0),
    0
  );

  const controlEvidence = policy.mappings.map(item => {
    const count = findings.filter(finding => finding.testId === item.testId)
      .reduce((sum, finding) => sum + finding.occurrences, 0);
    return {
      controlId: item.controlId,
      title: item.title,
      relatedTestId: item.testId,
      findingRecords: count,
      status: count ? "needs-review" : "not-assessed",
      fullControlAssessed: false,
      relationship: item.relationship,
    };
  });

  const result = {
    schemaVersion: 1,
    status: "review-required",
    provider: {
      name: expected.name,
      programVersion: expected.programVersion,
      packageVersion: expected.packageVersion,
    },
    framework: policy.framework,
    scope: {
      ...policy.scope,
      nonRootAcquisitionRecordValidated: true,
      pluginsDisabledInAcquisitionRecord: true,
      privilegedAndOrganizationalCoverageIncomplete: true,
      executedAndSkippedTestListsNotInterpreted: true,
    },
    provenance: {
      reportSha256: reportHash,
      processMetadataSha256: sha256(metadataBytes),
      policySha256: POLICY_HASH,
      providerExecutableSha256: expected.executableSha256,
      profileSha256: expected.profileSha256,
      acquisitionRepositoryBaseline: metadata.repositoryBaseline,
      verification: "structural-record-and-digest-checks-not-cryptographic-attestation",
    },
    sanitization: {
      rawHostFieldsOmitted: true,
      rawFindingTextOmitted: true,
      omittedContinuationLines,
      omittedHyphenatedFields,
    },
    summary: {
      warningRecords,
      suggestionRecords,
      findingRecords: warningRecords + suggestionRecords,
      mappedFindingRecords: mappedRecords,
      unmappedFindingRecords: warningRecords + suggestionRecords - mappedRecords,
      providerTestsDone: testsDone,
    },
    providerMetric: {
      hardeningIndex,
      isNistCompliancePercentage: false,
    },
    findings,
    controlEvidence,
    nistComplianceEstablished: false,
    cmmcCertificationEstablished: false,
    productionReady: false,
    deploymentAuthorized: false,
    releaseAuthorized: false,
    taskComplete: false,
  };

  if (Buffer.byteLength(JSON.stringify(result)) > MAX_OUTPUT_BYTES) invalid();
  return result;
}

module.exports = Object.freeze({
  POLICY_HASH, MAX_REPORT_BYTES, MAX_METADATA_BYTES,
  sha256, strictJson, parsePolicyBytes, readBounded, readPolicyBytes, normalize,
});
