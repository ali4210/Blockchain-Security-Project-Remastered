const fs = require("node:fs");
const path = require("node:path");
const { createHash } = require("node:crypto");

const POLICY_HASH = "eef3af1f3adca840147cd4bae30623710c0705ba2ecb38e269e344af941009ff";
const POLICY_PATH = path.resolve(__dirname, "../config/production-readiness.json");

function validPolicy(policy) {
  return Boolean(
    policy && typeof policy === "object" && !Array.isArray(policy) &&
    Object.keys(policy).sort().join(",") ===
      "hardwareCheck,productionAllowEnabled,protectedReference,readinessIntentVariable,schemaVersion" &&
    policy.schemaVersion === 1 &&
    policy.protectedReference === "main" &&
    policy.readinessIntentVariable === "PRODUCTION_READINESS_REQUESTED" &&
    policy.productionAllowEnabled === false &&
    policy.hardwareCheck &&
    Object.keys(policy.hardwareCheck).sort().join(",") === "adapter,state" &&
    policy.hardwareCheck.state === "unconfigured" &&
    policy.hardwareCheck.adapter === null
  );
}

function parsePolicyBytes(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length > 8192 ||
      createHash("sha256").update(bytes).digest("hex") !== POLICY_HASH) {
    throw new Error("policy integrity failure");
  }
  const policy = JSON.parse(bytes.toString("utf8"));
  if (!validPolicy(policy)) throw new Error("unsupported readiness policy");
  return policy;
}

function readPolicy() {
  const info = fs.lstatSync(POLICY_PATH);
  if (!info.isFile() || info.isSymbolicLink()) {
    throw new Error("unexpected readiness policy input");
  }
  return parsePolicyBytes(fs.readFileSync(POLICY_PATH));
}

function report(status, reasons, requested, contextValid = false) {
  return {
    schemaVersion: 1,
    task: "P03-006",
    status,
    decision: status === "not-requested" ? "not-applicable" : "block",
    productionReadinessRequested: requested,
    productionReady: false,
    deploymentAuthorized: false,
    releaseAuthorized: false,
    targetReference: "main",
    ciMetadataValid: contextValid,
    hardwareCheck: {
      state: "unconfigured",
      executed: false,
      adapterConfigured: false,
    },
    reasons,
    expectedPolicySha256: POLICY_HASH,
    securityAcceptance: "not-established",
    taskComplete: false,
  };
}

function validContext(context) {
  if (!context || typeof context !== "object" || Array.isArray(context) ||
      Object.keys(context).some((key) =>
        !["gitlab", "branch", "protected", "commitSha", "pipelineId"].includes(key)
      )) return false;

  return context.gitlab === true &&
    typeof context.commitSha === "string" &&
    /^[0-9a-f]{40}$/.test(context.commitSha) &&
    typeof context.pipelineId === "string" &&
    /^[1-9][0-9]{0,19}$/.test(context.pipelineId) &&
    (context.branch === null ||
      (typeof context.branch === "string" &&
       /^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$/.test(context.branch))) &&
    (context.protected === null ||
      (typeof context.protected === "string" && context.protected.length <= 8));
}

function evaluate(context, requested, policy) {
  if (!validPolicy(policy)) {
    return report("blocked", ["policy-invalid"], null);
  }
  if (!["true", "false"].includes(requested)) {
    return report("blocked", ["readiness-request-invalid"], null);
  }

  const productionRequest = requested === "true";
  if (!validContext(context)) {
    return report("blocked", productionRequest
      ? ["ci-context-invalid", "hardware-check-unconfigured"]
      : ["ci-context-invalid"], productionRequest);
  }

  if (!productionRequest) {
    return report(
      "not-requested",
      ["development-verification-is-not-production-readiness"],
      false, true
    );
  }

  const reasons = [];
  if (context.branch !== policy.protectedReference) {
    reasons.push("production-reference-mismatch");
  }
  if (context.protected !== "true") {
    reasons.push("protected-reference-not-verified");
  }

  // No external health report, demo flag, or mock result is trusted.
  // An approved real collector must be designed before an allow path exists.
  reasons.push("hardware-check-unconfigured");
  return report("blocked", reasons, true, true);
}

function collectContext(env) {
  return {
    gitlab: env.CI === "true" && env.CI_SERVER_NAME === "GitLab",
    branch: env.CI_COMMIT_BRANCH ?? null,
    protected: env.CI_COMMIT_REF_PROTECTED ?? null,
    commitSha: env.CI_COMMIT_SHA ?? null,
    pipelineId: env.CI_PIPELINE_ID ?? null,
  };
}

function main(args, env = process.env) {
  if (args.length !== 1 ||
      !["--ci", "--check-production-readiness"].includes(args[0])) {
    throw new Error("explicit readiness execution mode required");
  }
  const policy = readPolicy();
  if (args[0] === "--check-production-readiness") {
    return evaluate({
      gitlab: false, branch: null, protected: null,
      commitSha: null, pipelineId: null,
    }, "true", policy);
  }
  const requested = env[policy.readinessIntentVariable] ?? "false";
  return evaluate(collectContext(env), requested, policy);
}

module.exports = {
  POLICY_HASH, parsePolicyBytes, readPolicy, evaluate, collectContext, main,
};

if (require.main === module) {
  let decision;
  try {
    decision = main(process.argv.slice(2));
  } catch {
    decision = report("blocked", ["policy-or-invocation-invalid"], null);
  }
  process.stdout.write(JSON.stringify(decision, null, 2) + "\n");
  process.exitCode = decision.status === "not-requested" ? 0 : 1;
}
