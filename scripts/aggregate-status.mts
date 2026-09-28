// TODO(phase-14): Zone 9 — status aggregator. See blueprint Section 4E.3.
// Reads every zone's output and writes ONE status.json — the only input
// generate-html-report.mts needs. Never include raw sealed evidence, a
// private key or key-share, or an unredacted SAR — summary fields and
// pre-redacted excerpts only (each already sanitized by its own zone).
//
// Fields to populate (see the table in Section 4E.3):
//   findings[]              <- Zone 3 broker store (normalize-reports /
//                               enrich-findings output)
//   incidents[]              <- Zone 4 Incident Orchestrator log
//   forensicCases[]          <- Zone 5 report generator, REDACTED fields only
//   consensusAlerts[]        <- Zone 6 mcp-tool-consensus-monitor log
//   walletAuditFindings[]    <- Zone 7 mcp-tool-wallet-audit results
//   complianceRegister[]     <- Zone 8 mcp-tool-compliance-screen (21-col shape)
//   benchmarks               <- Upgrade 3 / Zone 5 benchmark suite
//   mlResults                <- Upgrade 3 benchmark suite (confusion matrix data)
export async function aggregateStatus(): Promise<void> {
  throw new Error("not implemented — see checklist Phase 14");
}
