import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import { StatusJsonOutput } from "./aggregate-status.mts";

function escapeHtml(str: string | null | undefined): string {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// --- One consistent badge system for every status/verdict/severity shown in
// the report, instead of each section hand-rolling its own colors. ---
type Tone = "green" | "red" | "amber" | "gray" | "blue";
const TONE_STYLE: Record<Tone, string> = {
  green: "color:#22c55e; background:rgba(34,197,94,0.14); border:1px solid rgba(34,197,94,0.4);",
  red: "color:#ef4444; background:rgba(239,68,68,0.14); border:1px solid rgba(239,68,68,0.4);",
  amber: "color:#eab308; background:rgba(234,179,8,0.14); border:1px solid rgba(234,179,8,0.4);",
  gray: "color:#94a3b8; background:rgba(148,163,184,0.14); border:1px solid rgba(148,163,184,0.4);",
  blue: "color:#38bdf8; background:rgba(56,189,248,0.14); border:1px solid rgba(56,189,248,0.4);",
};

function badge(label: string, tone: Tone): string {
  return `<span style="display:inline-block; padding:2px 9px; border-radius:4px; font-size:11px; font-weight:700; letter-spacing:0.2px; ${TONE_STYLE[tone]}">${escapeHtml(label)}</span>`;
}

function toneForGateStatus(status: string): Tone {
  const s = (status || "").toLowerCase();
  if (s === "ok") return "green";
  if (s === "error") return "red";
  if (s === "not_run") return "amber";
  return "gray";
}

function toneForVerdict(verdict: string): Tone {
  const v = (verdict || "").toUpperCase();
  if (v === "PASS") return "green";
  if (v === "HALT") return "red";
  return "amber"; // UNKNOWN
}

function toneForSeverity(sev: string): Tone {
  const s = (sev || "INFO").toUpperCase();
  if (s === "CRITICAL" || s === "HIGH") return "red";
  if (s === "MEDIUM") return "amber";
  if (s === "LOW") return "blue";
  return "gray";
}

function toneForFindingStatus(status: string): Tone {
  const s = (status || "").toUpperCase();
  if (s === "OPEN") return "red";
  if (s === "MITIGATED" || s === "REJECTED") return "amber";
  if (s === "VERIFIED" || s === "DISPATCHED" || s === "PASS") return "green";
  return "gray";
}

function renderDonutChart(crit: number, high: number, med: number, low: number): string {
  const total = crit + high + med + low || 1;
  const pCrit = (crit / total) * 100;
  const pHigh = (high / total) * 100;
  const pMed = (med / total) * 100;
  const pLow = (low / total) * 100;

  return `
    <div style="display:flex; align-items:center; gap:20px;">
      <svg width="110" height="110" viewBox="0 0 42 42" style="transform: rotate(-90deg);">
        <circle cx="21" cy="21" r="15.915" fill="transparent" stroke="#1e293b" stroke-width="5"></circle>
        <circle cx="21" cy="21" r="15.915" fill="transparent" stroke="#ef4444" stroke-width="5" stroke-dasharray="${pCrit} ${100 - pCrit}" stroke-dashoffset="0"></circle>
        <circle cx="21" cy="21" r="15.915" fill="transparent" stroke="#f97316" stroke-width="5" stroke-dasharray="${pHigh} ${100 - pHigh}" stroke-dashoffset="-${pCrit}"></circle>
        <circle cx="21" cy="21" r="15.915" fill="transparent" stroke="#eab308" stroke-width="5" stroke-dasharray="${pMed} ${100 - pMed}" stroke-dashoffset="-${pCrit + pHigh}"></circle>
        <circle cx="21" cy="21" r="15.915" fill="transparent" stroke="#3b82f6" stroke-width="5" stroke-dasharray="${pLow} ${100 - pLow}" stroke-dashoffset="-${pCrit + pHigh + pMed}"></circle>
      </svg>
      <div style="font-size:12px; display:flex; flex-direction:column; gap:6px;">
        <div><span style="color:#ef4444">■</span> Critical: <b>${crit}</b></div>
        <div><span style="color:#f97316">■</span> High: <b>${high}</b></div>
        <div><span style="color:#eab308">■</span> Medium: <b>${med}</b></div>
        <div><span style="color:#3b82f6">■</span> Low: <b>${low}</b></div>
      </div>
    </div>`;
}

function renderTrendSparkline(trend: StatusJsonOutput["trend"]): string {
  if (!trend || trend.length === 0) {
    return `<div style="font-size:12px; color:#94a3b8;">No run history yet — this view was added on ${new Date().toISOString().slice(0, 10)} and only tracks runs from here forward (reports/run-history.jsonl). It is not backfilled.</div>`;
  }
  const rows = trend
    .slice()
    .reverse()
    .map(
      (t) => `
    <tr>
      <td style="font-family:monospace; font-size:11px;">${escapeHtml(t.timestamp)}</td>
      <td style="font-family:monospace; font-size:11px;">${escapeHtml(t.commitSha.slice(0, 10))}</td>
      <td style="font-family:monospace; font-size:11px;">${escapeHtml(t.target.split("/").pop() || t.target)}</td>
      <td>${badge(t.health, toneForGateStatus(t.health === "OK" ? "ok" : "error"))}</td>
      <td>${badge(t.verdict, toneForVerdict(t.verdict))}</td>
      <td style="font-family:monospace; font-size:12px;">${t.criticalFindings} crit / ${t.highFindings} high / ${t.totalFindings} total</td>
    </tr>`
    )
    .join("");
  return `
    <p style="font-size:12px; color:#94a3b8; margin-bottom:10px;">Last ${trend.length} run(s) recorded in <code>reports/run-history.jsonl</code> since this view was added — a real, growing history, never backfilled with invented past runs.</p>
    <table>
      <thead><tr><th>Run Timestamp</th><th>Commit</th><th>Target</th><th>Health</th><th>Verdict</th><th>Findings</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}

export async function generateHtmlReport(statusJsonPath?: string): Promise<string> {
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const defaultPath = resolve(process.cwd(), "reports/status.json");
  const targetJsonPath = statusJsonPath ? resolve(process.cwd(), statusJsonPath) : defaultPath;

  if (!existsSync(targetJsonPath)) {
    throw new Error(`Target status file does not exist: ${targetJsonPath}`);
  }

  const data: StatusJsonOutput = JSON.parse(readFileSync(targetJsonPath, "utf-8"));
  const v104 = data.enterprise_v10_4 || {};
  const ddj = data.defectdojo_compliance;
  const targetName = (data.pipeline?.target || "").split("/").pop() || data.pipeline?.target || "unknown";

  // --- Executive summary paragraph, generated from this run's real verdict ---
  const healthOk = data.pipeline?.health === "OK";
  const verdict = data.pipeline?.verdict || "UNKNOWN";
  const summaryParts: string[] = [];
  if (!healthOk) {
    summaryParts.push(
      `Pipeline HEALTH is FAILED: ${(data.pipeline?.healthProblems || []).join("; ") || "one or more required scanners did not run cleanly"}. The verdict below is only as trustworthy as that gap allows.`
    );
  }
  if (verdict === "PASS") {
    summaryParts.push(`All required security gates passed for ${escapeHtml(targetName)}. No high/critical findings blocked this run.`);
  } else if (verdict === "HALT") {
    summaryParts.push(
      `This run HALTS deployment of ${escapeHtml(targetName)}. Reason(s): ${(data.pipeline?.haltReasons || []).join("; ") || "see gate detail below"}.`
    );
  } else {
    summaryParts.push(`Verdict is UNKNOWN for ${escapeHtml(targetName)} — not enough of this run's real data was available to make a ship/no-ship call.`);
  }
  const execSummary = summaryParts.join(" ");

  // --- Gate-by-gate table ---
  const gateRows = (data.gates || [])
    .map(
      (g) => `
    <tr>
      <td><b>${escapeHtml(g.name)}</b></td>
      <td style="font-family:monospace; font-size:11px; color:#94a3b8;">${escapeHtml(g.tool || "")}</td>
      <td>${badge((g.policy || "informational").toUpperCase(), g.policy === "required" ? "blue" : "gray")}</td>
      <td>${badge((g.status || "unknown").toUpperCase(), toneForGateStatus(g.status))}</td>
      <td style="font-size:12px; color:#cbd5e1;">${escapeHtml(g.detail || "")}${g.counts ? ` <span style="color:#64748b; font-family:monospace;">${escapeHtml(JSON.stringify(g.counts))}</span>` : ""}</td>
    </tr>`
    )
    .join("");

  // --- Master findings table (searchable) ---
  const findingRows = (data.findings || [])
    .map(
      (f) => `
    <tr>
      <td style="font-family:monospace; font-size:12px;">${escapeHtml(f.id)}</td>
      <td>${badge(f.severity, toneForSeverity(f.severity))}</td>
      <td><span style="font-size:11px; background:#1e293b; padding:2px 6px; border-radius:4px;">${escapeHtml(f.zone)}</span></td>
      <td><b>${escapeHtml(f.title)}</b><div style="font-size:12px; color:#94a3b8; margin-top:2px;">${escapeHtml(f.description)}</div></td>
      <td style="font-family:monospace; font-size:11px; color:#cbd5e1;">${escapeHtml(f.target || "N/A")}</td>
      <td>${badge(f.status, toneForFindingStatus(f.status))}</td>
    </tr>`
    )
    .join("");

  const walletRows = (data.walletAuditFindings || [])
    .map(
      (w) => `
    <tr>
      <td style="font-family:monospace; font-size:12px;">${escapeHtml(w.findingId)}</td>
      <td><b>${escapeHtml(w.vulnerabilityClass)}</b></td>
      <td>${badge(w.status, toneForFindingStatus(w.status))}</td>
    </tr>`
    )
    .join("");

  const forensicRows = (data.forensicCases || [])
    .map(
      (c) => `
    <tr>
      <td style="font-family:monospace; font-size:12px;">${escapeHtml(c.caseId)}</td>
      <td style="font-family:monospace; font-size:11px; color:#93c5fd;">${escapeHtml(c.targetAddress || "—")}</td>
      <td style="font-family:monospace;">${c.sealedArtifactsCount} file(s)</td>
      <td>${badge(c.integrityVerified ? "CHAIN VERIFIED" : "UNVERIFIED", c.integrityVerified ? "green" : "red")}</td>
      <td style="font-size:12px; color:#94a3b8;">${escapeHtml(c.redactedSummary)}</td>
    </tr>`
    )
    .join("");

  const complianceRows = (data.complianceRegister || [])
    .map(
      (cr) => `
    <tr>
      <td style="font-family:monospace; font-size:11px; color:#cbd5e1;">${escapeHtml(cr.entityAddress)}</td>
      <td>${badge(cr.sanctionMatch ? "SDN MATCH" : "CLEAN", cr.sanctionMatch ? "red" : "green")}</td>
      <td>${badge(cr.riskTier, cr.sanctionMatch ? "red" : "green")}</td>
      <td style="font-size:12px; color:#94a3b8;">${escapeHtml(cr.reason || "")}</td>
    </tr>`
    )
    .join("");

  const incidentRows = (data.incidents || [])
    .map(
      (i) => `
    <tr>
      <td style="font-family:monospace; font-size:12px;">${escapeHtml(i.id)}</td>
      <td>${escapeHtml(i.title)}</td>
      <td>${badge(i.severity, toneForSeverity(i.severity))}</td>
      <td>${badge(i.status, toneForFindingStatus(i.status))}</td>
      <td style="font-family:monospace; font-size:11px; color:#94a3b8;">${escapeHtml(i.createdAt)}</td>
    </tr>`
    )
    .join("");

  const consensusRows = (data.consensusAlerts || [])
    .map(
      (a) => `
    <tr>
      <td style="font-family:monospace; font-size:12px;">${escapeHtml(a.alertId)}</td>
      <td>${escapeHtml(a.anomalyType)}</td>
      <td>${badge(a.severity, toneForSeverity(a.severity))}</td>
      <td>${badge(a.avsQuorumConfirmed ? "QUORUM CONFIRMED" : "NOT CONFIRMED", a.avsQuorumConfirmed ? "red" : "green")}</td>
      <td style="font-family:monospace; font-size:11px; color:#94a3b8;">${escapeHtml(a.timestamp)}</td>
    </tr>`
    )
    .join("");

  const openFlaws = (data.findings || []).filter((f) => f.status === "OPEN");

  let html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(data.system.name)} — Executive Security Report</title>
  <style>
    :root {
      --bg-primary: #0b0f17;
      --bg-secondary: #111827;
      --bg-card: #162032;
      --border-color: #243247;
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
      --accent: #38bdf8;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg-primary);
      color: var(--text-main);
      font-family: system-ui, -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
      line-height: 1.5;
      padding: 30px;
    }
    .container { max-width: 1350px; margin: 0 auto; }
    header {
      border-bottom: 1px solid var(--border-color);
      padding-bottom: 20px;
      margin-bottom: 24px;
      display: flex;
      justify-content: space-between;
      align-items: flex-end;
      flex-wrap: wrap;
      gap: 12px;
    }
    h1 { font-size: 24px; font-weight: 700; color: #fff; }
    .meta { font-size: 13px; color: var(--text-muted); margin-top: 5px; }
    .verdict-banner {
      display: flex; align-items: center; gap: 16px;
      padding: 18px 22px; border-radius: 10px; margin-bottom: 24px;
      background: var(--bg-card); border: 1px solid var(--border-color);
    }
    .verdict-banner .big-badge { font-size: 20px; padding: 8px 18px; border-radius: 8px; font-weight: 800; letter-spacing: 0.5px; }
    .verdict-banner p { font-size: 14px; color: #e2e8f0; max-width: 900px; }
    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
      gap: 16px;
      margin-bottom: 28px;
    }
    .kpi-card {
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 16px;
    }
    .kpi-title { font-size: 11px; color: var(--text-muted); text-transform: uppercase; font-weight: 600; letter-spacing: 0.5px; }
    .kpi-value { font-size: 26px; font-weight: 700; margin-top: 6px; color: #fff; }
    .kpi-sub { font-size: 11px; color: var(--text-muted); margin-top: 4px; }
    .section-card {
      background: var(--bg-secondary);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 22px;
      margin-bottom: 24px;
    }
    .section-title { font-size: 16px; font-weight: 600; margin-bottom: 6px; border-bottom: 1px solid var(--border-color); padding-bottom: 8px; }
    .section-sub { font-size: 12px; color: var(--text-muted); margin-bottom: 12px; }
    table { width: 100%; border-collapse: collapse; margin-top: 10px; }
    th { text-align: left; padding: 10px 12px; font-size: 11px; text-transform: uppercase; color: var(--text-muted); border-bottom: 1px solid var(--border-color); }
    td { padding: 12px; font-size: 13px; border-bottom: 1px solid #1a2538; vertical-align: top; }
    tr:hover { background: rgba(255, 255, 255, 0.02); }
    .toolbar { display: flex; gap: 12px; margin-bottom: 15px; }
    .search-input {
      background: var(--bg-primary);
      border: 1px solid var(--border-color);
      border-radius: 6px;
      color: #fff;
      padding: 8px 14px;
      font-size: 13px;
      width: 320px;
    }
    .btn {
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      color: var(--text-main);
      padding: 8px 14px;
      border-radius: 6px;
      font-size: 13px;
      cursor: pointer;
    }
    .btn:hover { background: #1e2c45; }
    .grid-2 { display: grid; grid-template-columns: repeat(auto-fit, minmax(380px, 1fr)); gap: 20px; }
    .empty-note { font-size: 12px; color: var(--text-muted); padding: 10px 0; }
    .cumulative-flag { font-size: 10px; color: #eab308; background: rgba(234,179,8,0.12); border: 1px solid rgba(234,179,8,0.4); padding: 1px 6px; border-radius: 4px; margin-left: 6px; }
    @media print {
      body { background: #fff; color: #000; padding: 0; }
      .section-card, .kpi-card, .verdict-banner { border: 1px solid #ccc; background: #fff; color: #000; }
      .toolbar { display: none; }
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <h1>${escapeHtml(data.system.name)} — Executive Security Report</h1>
        <div class="meta">Generated: ${escapeHtml(data.timestamp)} | Commit: <code>${escapeHtml(data.system.commitSha.slice(0, 10))}</code> | Release: ${escapeHtml(data.system.version)} | Target: <code>${escapeHtml(targetName)}</code></div>
      </div>
      <div>
        <button class="btn" onclick="window.print()">Print / Export PDF</button>
      </div>
    </header>

    <!-- EXECUTIVE SUMMARY -->
    <div class="verdict-banner">
      <div class="big-badge" style="${TONE_STYLE[toneForVerdict(verdict)]}">${escapeHtml(verdict)}</div>
      <div class="big-badge" style="${TONE_STYLE[toneForGateStatus(healthOk ? "ok" : "error")]}">HEALTH: ${escapeHtml(data.pipeline?.health || "UNKNOWN")}</div>
      <p>${execSummary}</p>
    </div>

    <div class="kpi-grid">
      <div class="kpi-card">
        <div class="kpi-title">Total Findings (this run)</div>
        <div class="kpi-value">${data.metrics.totalFindings}</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-title">Critical &amp; High (this run)</div>
        <div class="kpi-value" style="color: #ef4444;">${data.metrics.criticalFindings + data.metrics.highFindings}</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-title">Required Gates Passing</div>
        <div class="kpi-value" style="color: ${data.metrics.complianceScorePct === 100 ? '#22c55e' : '#eab308'};">${data.metrics.complianceScorePct}%</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-title">Active Consensus Alerts</div>
        <div class="kpi-value">${data.metrics.activeConsensusAlerts}</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-title">Forensic Cases Sealed (this run)</div>
        <div class="kpi-value">${data.metrics.forensicCasesSealed}</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-title">DefectDojo Unique Flaws <span class="cumulative-flag">CUMULATIVE</span></div>
        <div class="kpi-value" style="color: #38bdf8;">${ddj?.active_unique_findings ?? "N/A"}</div>
        <div class="kpi-sub">Across all historical runs ingested into DefectDojo — not this run's count.</div>
      </div>
    </div>

    <!-- GATE-BY-GATE STATUS BREAKDOWN -->
    <div class="section-card">
      <div class="section-title">Gate-by-Gate Status (this run)</div>
      <div class="section-sub">Every real scanner/consensus result this pipeline run produced under <code>reports/scanners/*.json</code>. BLUE policy = required for the ship/no-ship verdict; GRAY = informational signal only.</div>
      <table>
        <thead><tr><th>Gate</th><th>Tool</th><th>Policy</th><th>Status</th><th>Detail</th></tr></thead>
        <tbody>${gateRows || `<tr><td colspan="5" class="empty-note">No gate results found for this run.</td></tr>`}</tbody>
      </table>
    </div>

    <!-- PER-SUBSYSTEM DETAIL -->
    <div class="grid-2">
      <div class="section-card">
        <div class="section-title">AVS Consensus (3-Node Live EVM Execution)</div>
        <div class="section-sub">${v104.avs_consensus ? `${escapeHtml(v104.avs_consensus.protocol)} — ${escapeHtml(v104.avs_consensus.topology)}` : "No AVS consensus result this run."}</div>
        ${
          v104.avs_consensus
            ? `<p style="font-size:13px;">Decision: ${badge(v104.avs_consensus.decision, v104.avs_consensus.consensus_reached && v104.avs_consensus.decision?.includes("EXPLOIT") ? "red" : "green")} &nbsp; Agreement: <b>${escapeHtml(v104.avs_consensus.agreement_ratio)}</b> across ports ${escapeHtml((v104.avs_consensus.ports || []).join(", "))}</p>`
            : ""
        }
      </div>
      <div class="section-card">
        <div class="section-title">LangGraph 7-Agent Swarm</div>
        <div class="section-sub">${v104.langgraph_swarm ? `${v104.langgraph_swarm.agents_count} agents via ${escapeHtml(v104.langgraph_swarm.framework)}` : "No swarm result this run."}</div>
        ${
          v104.langgraph_swarm
            ? `<p style="font-size:13px;">Decision: ${badge(v104.langgraph_swarm.decision, v104.langgraph_swarm.decision === "HALT_CONFIRMED" ? "red" : "green")} &nbsp; Votes: ${escapeHtml(JSON.stringify(v104.langgraph_swarm.votes || {}))}</p>`
            : ""
        }
      </div>
      <div class="section-card">
        <div class="section-title">Infrastructure: Vault &amp; Kubernetes</div>
        <table>
          <tbody>
            <tr><td>HashiCorp Vault (Transit)</td><td>${v104.hashicorp_vault ? badge(v104.hashicorp_vault.status, toneForGateStatus(v104.hashicorp_vault.status)) : badge("NOT RUN", "gray")}</td><td style="font-size:12px; color:#94a3b8;">${escapeHtml(v104.hashicorp_vault?.detail || "")}</td></tr>
            <tr><td>K3s Kubernetes</td><td>${v104.k3s_kubernetes ? badge(v104.k3s_kubernetes.status, toneForGateStatus(v104.k3s_kubernetes.status)) : badge("NOT RUN", "gray")}</td><td style="font-size:12px; color:#94a3b8;">${escapeHtml(v104.k3s_kubernetes?.node || "")} ${escapeHtml(v104.k3s_kubernetes?.version || "")} ${escapeHtml(v104.k3s_kubernetes?.detail || "")}</td></tr>
          </tbody>
        </table>
      </div>
      <div class="section-card">
        <div class="section-title">OWASP Smart Contract Coverage</div>
        <p style="font-size:13px; color:#cbd5e1;">Categories actually triggered this run: <b>${escapeHtml(v104.owasp_sc_top_10 || "none")}</b></p>
        <p style="font-size:12px; color:#94a3b8; margin-top:8px;">OpenSCAP: ${v104.openscap ? badge(v104.openscap.status, toneForGateStatus(v104.openscap.status === "AUDITED_ACTIVE" ? "ok" : v104.openscap.status === "ERROR" ? "error" : "not_run")) : badge("NOT RUN", "gray")} <span style="margin-left:6px;">${escapeHtml(v104.openscap?.standard || "")}</span></p>
      </div>
    </div>

    <!-- WALLET / FORENSICS / INCIDENTS -->
    <div class="section-card">
      <div class="section-title">Wallet Pre-Sign Simulation</div>
      <table>
        <thead><tr><th>Audit ID</th><th>Check</th><th>Status</th></tr></thead>
        <tbody>${walletRows || `<tr><td colspan="3" class="empty-note">No pre-sign simulation result this run.</td></tr>`}</tbody>
      </table>
    </div>

    <div class="section-card">
      <div class="section-title">Forensics &amp; Chain of Custody</div>
      <table>
        <thead><tr><th>Case ID</th><th>Related Address</th><th>Sealed Artifacts</th><th>Integrity</th><th>Summary</th></tr></thead>
        <tbody>${forensicRows || `<tr><td colspan="5" class="empty-note">No evidence seal recorded this run.</td></tr>`}</tbody>
      </table>
    </div>

    <div class="section-card">
      <div class="section-title">Incident Response Dispatch</div>
      <table>
        <thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Status</th><th>Created</th></tr></thead>
        <tbody>${incidentRows || `<tr><td colspan="5" class="empty-note">No incident dispatched this run.</td></tr>`}</tbody>
      </table>
    </div>

    <div class="section-card">
      <div class="section-title">Consensus Alerts</div>
      <table>
        <thead><tr><th>Alert ID</th><th>Type</th><th>Severity</th><th>AVS Quorum</th><th>Time</th></tr></thead>
        <tbody>${consensusRows || `<tr><td colspan="5" class="empty-note">No active consensus alerts this run.</td></tr>`}</tbody>
      </table>
    </div>

    <!-- OFAC / COMPLIANCE REGISTER -->
    <div class="section-card">
      <div class="section-title">OFAC Sanctions Screening</div>
      <table>
        <thead><tr><th>Counterparty Address</th><th>Sanction Status</th><th>Risk Tier</th><th>Detail</th></tr></thead>
        <tbody>${complianceRows || `<tr><td colspan="4" class="empty-note">No addresses screened this run.</td></tr>`}</tbody>
      </table>
    </div>

    <!-- SEVERITY BREAKDOWN -->
    <div class="section-card">
      <div class="section-title">Severity Breakdown (this run's findings)</div>
      ${renderDonutChart(data.metrics.criticalFindings, data.metrics.highFindings, data.metrics.mediumFindings, data.metrics.lowFindings)}
    </div>

    <!-- TREND / RUN HISTORY -->
    <div class="section-card">
      <div class="section-title">Run History / Trend</div>
      ${renderTrendSparkline(data.trend)}
    </div>

    <!-- MASTER FINDINGS TABLE -->
    <div class="section-card">
      <div class="section-title">Master Security Findings Register</div>
      <div class="toolbar">
        <input type="text" id="findingSearch" class="search-input" placeholder="Live search title, rule, target..." onkeyup="filterFindings()">
      </div>
      <table id="findingsTable">
        <thead><tr><th>ID</th><th>Severity</th><th>Zone</th><th>Finding &amp; Details</th><th>Target Context</th><th>Status</th></tr></thead>
        <tbody>${findingRows || `<tr><td colspan="6" class="empty-note">No findings recorded this run.</td></tr>`}</tbody>
      </table>
    </div>

  </div>

  <script>
    function filterFindings() {
      const input = document.getElementById("findingSearch");
      const filter = input.value.toLowerCase();
      const rows = document.querySelectorAll("#findingsTable tbody tr");
      for (const row of rows) {
        const text = row.innerText.toLowerCase();
        row.style.display = text.includes(filter) ? "" : "none";
      }
    }
  </script>
</body>
</html>`;

  const outDir = resolve(process.cwd(), "reports");
  if (!existsSync(outDir)) {
    mkdirSync(outDir, { recursive: true });
  }

  const outPath = resolve(outDir, `project-status-${timestamp}.html`);
  const latestPath = resolve(outDir, "latest.html");

  writeFileSync(outPath, html, "utf-8");
  writeFileSync(latestPath, html, "utf-8");

  console.log(`[+] Generated executive report: ${outPath}`);
  console.log(`[+] Synced latest report: ${latestPath}`);

  return outPath;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  generateHtmlReport(process.argv[2]).catch((err) => {
    console.error("[-] Report generation error:", err);
    process.exit(1);
  });
}
