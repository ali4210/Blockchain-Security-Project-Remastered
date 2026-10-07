const { createHash } = require("node:crypto");

function object(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function verifySha256(content, expected) {
  if (!/^[0-9a-f]{64}$/.test(expected)) {
    throw new Error("invalid expected SHA-256");
  }
  const actual = createHash("sha256").update(content).digest("hex");
  if (actual !== expected) throw new Error("SHA-256 mismatch");
  return actual;
}

function classifyScanner(tool, exitCode, report) {
  const invalid = (reason) => ({
    execution: "error", reason, findingCount: null,
    securityAcceptance: "not-established",
  });
  if (!["slither", "mythril"].includes(tool)) return invalid("unsupported tool");
  if (!Number.isInteger(exitCode)) return invalid("missing process exit status");
  if (!object(report) || report.success !== true || report.error != null) {
    return invalid("scanner report does not declare successful execution");
  }
  const findings = tool === "slither"
    ? report.results?.detectors
    : report.issues;
  if (!Array.isArray(findings) || findings.some((item) => !object(item))) {
    return invalid("invalid findings list");
  }
  const exitAccepted = tool === "slither"
    ? exitCode === 0
    : exitCode === 0 || (exitCode === 1 && findings.length > 0);
  if (!exitAccepted) return invalid("inconsistent or unsupported exit status");
  return {
    execution: "completed",
    outcome: findings.length ? "findings" : "no-findings-within-scope",
    findingCount: findings.length,
    securityAcceptance: "not-established",
  };
}

function classifySmt(exitCode, report, target) {
  const result = (status, reason) => ({ status, reason });
  if (!Number.isInteger(exitCode) || exitCode !== 0 || !object(report)) {
    return result("error", "compiler execution failed or report malformed");
  }
  const diagnostics = report.errors ?? [];
  if (!Array.isArray(diagnostics) || diagnostics.some((item) => !object(item))) {
    return result("error", "invalid compiler diagnostics");
  }
  if (diagnostics.some((item) => item.severity === "error")) {
    return result("error", "compiler error diagnostic");
  }
  const messages = diagnostics.map((item) => String(item.message ?? ""));
  if (messages.some((message) =>
    /not available|no horn solver|no smt solver|analysis was not possible/i.test(message)
  )) {
    return result("unavailable", "solver unavailable or analysis skipped");
  }
  if (!object(target) || !["chc", "bmc"].includes(target.engine) ||
      typeof target.file !== "string" ||
      !Number.isInteger(target.start) || !Number.isInteger(target.end) ||
      target.start < 0 || target.end <= target.start) {
    return result("error", "invalid target identity");
  }
  const prefix = target.engine.toUpperCase();
  const statuses = new Set();
  for (const item of diagnostics) {
    const location = item.sourceLocation;
    if (!object(location) || location.file !== target.file ||
        !Number.isInteger(location.start) || !Number.isInteger(location.end) ||
        location.start >= target.end || location.end <= target.start) continue;
    const message = String(item.message ?? "");
    if (message.includes(`${prefix}: Assertion violation check is safe!`)) {
      statuses.add("safe");
    }
    if (message.includes(`${prefix}: Assertion violation happens here.`)) {
      statuses.add("violated");
    }
    if (message.includes(`${prefix}: Assertion violation might happen here.`)) {
      statuses.add("unknown");
    }
  }
  if (statuses.size > 1) return result("error", "conflicting target diagnostics");
  if (statuses.size === 0) return result("unknown", "no recognized target result");
  return result([...statuses][0], "target-specific diagnostic");
}

module.exports = { verifySha256, classifyScanner, classifySmt };
