// One-off generator for a real, full-coverage Grafana dashboard JSON covering
// every blockchain_soc_* metric family actually exported to :9101/metrics.
// Not part of the pipeline; run once to (re)produce the dashboard file that
// gets deployed to /srv/devsecops/grafana/provisioning/dashboards/.
import { writeFileSync } from "node:fs";

const DS = { type: "prometheus", uid: "prometheus-default" };
let id = 1;
let y = 0;
const COLS = 4;
const W = 24 / COLS;
const H = 6;
let col = 0;
const panels = [];

function nextPos() {
  const x = col * W;
  if (col === 0 && panels.length > 0) y += H;
  col = (col + 1) % COLS;
  return { h: H, w: W, x, y };
}

function statPanel(title, expr, opts = {}) {
  panels.push({
    id: id++,
    gridPos: nextPos(),
    title,
    type: "stat",
    datasource: DS,
    targets: [{ datasource: DS, expr, instant: true, format: "time_series", refId: "A" }],
    fieldConfig: {
      defaults: {
        color: { mode: "thresholds" },
        thresholds: {
          mode: "absolute",
          steps: opts.steps || [{ color: "green", value: null }, { color: "red", value: 1 }],
        },
        ...(opts.mappings ? { mappings: opts.mappings } : {}),
      },
    },
    options: { colorMode: "background", graphMode: "none", justifyMode: "center",
               reduceOptions: { calcs: ["lastNotNull"], fields: "", values: false } },
  });
}

function gaugePanel(title, expr, max = 10) {
  panels.push({
    id: id++,
    gridPos: nextPos(),
    title,
    type: "gauge",
    datasource: DS,
    targets: [{ datasource: DS, expr, instant: true, format: "time_series", refId: "A" }],
    fieldConfig: { defaults: { min: 0, max, thresholds: { mode: "absolute",
      steps: [{ color: "green", value: null }, { color: "orange", value: max * 0.4 }, { color: "red", value: max * 0.7 }] } } },
  });
}

function tablePanel(title, expr) {
  panels.push({
    id: id++,
    gridPos: { h: H, w: 24, x: 0, y: (y += (col === 0 ? 0 : H)) },
    title,
    type: "table",
    datasource: DS,
    targets: [{ datasource: DS, expr, instant: true, format: "table", refId: "A" }],
    options: { showHeader: true },
  });
  col = 0;
}

function row(title) {
  if (col !== 0) { y += H; col = 0; }
  panels.push({ id: id++, gridPos: { h: 1, w: 24, x: 0, y }, title, type: "row", collapsed: false });
  y += 1;
}

row("Pipeline Health & Risk");
statPanel("Pipeline Execution Gate", "max(blockchain_soc_pipeline_success)",
  { mappings: [{ options: { "0": { color: "red", text: "PIPELINE FAILED" }, "1": { color: "green", text: "100% OPERATIONAL" } }, type: "value" }] });
gaugePanel("DREAD Risk Score (Max 10)", "max(blockchain_soc_dread_score)", 10);
statPanel("High-Entropy Secret Leaks", "max(blockchain_soc_gitleaks_findings)",
  { steps: [{ color: "green", value: null }, { color: "orange", value: 1 }, { color: "red", value: 10 }] });
gaugePanel("BFT Agreement Ratio", "max(blockchain_soc_bft_agreement_ratio)", 1);

row("Trivy / DefectDojo-Fed Vulnerability Counts");
statPanel("Trivy Critical", 'max(blockchain_soc_trivy_vulns{severity="critical"})');
statPanel("Trivy High", 'max(blockchain_soc_trivy_vulns{severity="high"})',
  { steps: [{ color: "green", value: null }, { color: "red", value: 1 }] });
statPanel("Slither Findings (Total)", "max(blockchain_soc_slither_findings_total)",
  { steps: [{ color: "green", value: null }, { color: "red", value: 1 }] });
statPanel("Mythril Findings (Total)", "max(blockchain_soc_mythril_findings_total)",
  { steps: [{ color: "green", value: null }, { color: "red", value: 1 }] });
tablePanel("SAST Findings by Tool + Severity (Slither / Mythril)", "blockchain_soc_sast_findings_by_severity");
tablePanel("Multi-Layer Tool Status (all integrated tools, 1=OK/Active 2=Halt/Tripped 0=Down)", "blockchain_soc_tool_status");

row("Section A-F: Newly Wired Detectors (this task's additions)");
statPanel("Consensus-Attack Checks Triggered (reorg/concentration/eclipse/selfish-mining)",
  "max(blockchain_soc_consensus_attack_checks_triggered)",
  { steps: [{ color: "green", value: null }, { color: "red", value: 1 }] });
statPanel("Flash-Loan-Shape Findings", 'max(blockchain_soc_flashloan_findings{kind="flashloan"})',
  { steps: [{ color: "green", value: null }, { color: "red", value: 1 }] });
statPanel("Front-Running Exposure Findings", 'max(blockchain_soc_flashloan_findings{kind="frontrunning"})',
  { steps: [{ color: "green", value: null }, { color: "red", value: 1 }] });
statPanel("Rug-Pull Failing Checks", "max(blockchain_soc_rugpull_failing_checks)",
  { steps: [{ color: "green", value: null }, { color: "red", value: 1 }] });
statPanel("SoftHSM2 PKCS#11 Sign+Verify OK", "max(blockchain_soc_hsm_signer_ok)",
  { mappings: [{ options: { "0": { color: "red", text: "FAILED" }, "1": { color: "green", text: "OK" } }, type: "value" }] });
statPanel("Quorum Signing (Shamir->MPC Joint-Sign) OK", "max(blockchain_soc_quorum_signer_ok)",
  { mappings: [{ options: { "0": { color: "red", text: "FAILED" }, "1": { color: "green", text: "OK" } }, type: "value" }] });
statPanel("Vyper Reentrancy-Shaped Findings", "max(blockchain_soc_vyper_reentrancy_findings)",
  { steps: [{ color: "green", value: null }, { color: "red", value: 1 }] });
statPanel("Echidna Properties Falsified", "max(blockchain_soc_echidna_properties_failing)",
  { steps: [{ color: "green", value: null }, { color: "red", value: 1 }] });

row("OWASP DSOMM Maturity");
statPanel("DSOMM Activities Assessed", "max(blockchain_soc_dsomm_activities_assessed_total)");
statPanel("DSOMM Activities Total (denominator)", "max(blockchain_soc_dsomm_activities_total)");
tablePanel("DSOMM Level by Subdimension", "blockchain_soc_dsomm_level");
tablePanel("DSOMM Coverage Ratio by Subdimension", "blockchain_soc_dsomm_coverage_ratio");
tablePanel("LangGraph Swarm Agent Verdicts", "blockchain_soc_agent_verdict");

if (col !== 0) y += H;

const dashboard = {
  id: null,
  uid: "blockchain-soc-full-coverage",
  title: "Autonomous Blockchain SOC — Full Metric Coverage",
  schemaVersion: 39,
  version: 2,
  editable: true,
  liveNow: true,
  graphTooltip: 1,
  time: { from: "now-24h", to: "now" },
  refresh: "30s",
  panels,
  annotations: { list: [] },
  tags: ["blockchain-soc", "full-coverage"],
};

writeFileSync(new URL("./blockchain-soc-full-coverage-dashboard.json", import.meta.url), JSON.stringify(dashboard, null, 2));
console.log(`Wrote dashboard with ${panels.length} panels (incl. ${panels.filter(p=>p.type==="row").length} row headers).`);
