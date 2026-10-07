#!/usr/bin/env node
"use strict";

const {
  MAX_REPORT_BYTES, MAX_METADATA_BYTES,
  readBounded, readPolicyBytes, normalize,
} = require("./governance-core.cjs");

function main() {
  const argumentsList = process.argv.slice(2);
  if (argumentsList.length !== 4 ||
      argumentsList[0] !== "--report" ||
      argumentsList[2] !== "--metadata" ||
      !argumentsList[1] || !argumentsList[3]) {
    throw new Error("invalid");
  }
  const result = normalize(
    readBounded(argumentsList[1], MAX_REPORT_BYTES),
    readBounded(argumentsList[3], MAX_METADATA_BYTES),
    readPolicyBytes(),
  );
  process.stdout.write(JSON.stringify(result) + "\n");
}

try {
  main();
} catch {
  process.stderr.write(JSON.stringify({
    schemaVersion: 1,
    status: "invalid",
    reason: "governance-input-invalid",
  }) + "\n");
  process.exitCode = 1;
}
