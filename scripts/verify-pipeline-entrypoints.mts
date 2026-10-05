import { readFileSync } from "node:fs";

type Input = {
  source?: unknown;
  payload?: unknown;
};

const pipelineEntry = "verify";
const requiredJobs = ["runner_smoke_test", "ingest_manifests"];

function invalid(message: string): never {
  throw new Error(message);
}

function requireObject(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    invalid(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function normalize(input: Input): Record<string, unknown> {
  const source = input.source;
  const payload = requireObject(input.payload, "payload");

  if (source === "developer_push") {
    if (payload.ref !== "refs/heads/main" || payload.event !== "push") {
      invalid("developer_push payload must declare event push on refs/heads/main");
    }
  } else if (source === "webhook") {
    if (payload.kind !== "manifest_ingestion" || payload.version !== 1) {
      invalid("webhook payload must declare manifest_ingestion version 1");
    }
  } else if (source === "on_chain_event_stub") {
    if (payload.event !== "ManifestRequested" || payload.schemaVersion !== 1) {
      invalid("on_chain_event_stub payload must declare ManifestRequested schemaVersion 1");
    }
  } else {
    invalid("source must be developer_push, webhook, or on_chain_event_stub");
  }

  return {
    schemaVersion: 1,
    status: "accepted",
    source,
    pipelineEntry,
    requiredJobs,
  };
}

function main(): void {
  const inputPath = process.argv[2];
  if (!inputPath) {
    invalid("usage: verify-pipeline-entrypoints.mts <input-json>");
  }

  const parsed = JSON.parse(readFileSync(inputPath, "utf8")) as Input;
  process.stdout.write(`${JSON.stringify(normalize(parsed))}\n`);
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
