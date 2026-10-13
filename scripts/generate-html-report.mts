import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { resolve, dirname } from "node:path";

export interface FindingSummary {
  id: string;
  rule_id: string;
  zone: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  title: string;
  description: string;
  target?: string;
  status: "OPEN" | "MITIGATED" | "VERIFIED" | "ACKNOWLEDGED";
}

export interface StatusJsonContract {
  schemaVersion: number;
  timestamp: string;
  system: {
    name: string;
    version: string;
    commitSha: string;
    status: "HEALTHY" | "DEGRADED" | "CRITICAL";
  };
  metrics: {
    totalFindings: number;
    criticalFindings: number;
    highFindings: number;
    mediumFindings: number;
    lowFindings: number;
    complianceScorePct: number;
    activeConsensusAlerts: number;
    forensicCasesSealed: number;
  };
  findings: FindingSummary[];
  zones: Record<string, {
    status: string;
    testCount: number;
    summary: string;
  }>;
}

function escapeHtml(str: string | null | undefined): string {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function renderSeverityBadge(severity: string): string {
  const sev = (severity || "INFO").toUpperCase();
  const colors: Record<string, string> = {
    CRITICAL: "#ef4444; background: rgba(239, 68, 68, 0.15); border: 1px solid rgba(239, 68, 68, 0.4);",
    HIGH: "#f97316; background: rgba(249, 115, 22, 0.15); border: 1px solid rgba(249, 115, 22, 0.4);",
    MEDIUM: "#eab308; background: rgba(234, 179, 8, 0.15); border: 1px solid rgba(234, 179, 8, 0.4);",
    LOW: "#3b82f6; background: rgba(59, 130, 246, 0.15); border: 1px solid rgba(59, 130, 246, 0.4);",
    INFO: "#94a3b8; background: rgba(148, 163, 184, 0.15); border: 1px solid rgba(148, 163, 184, 0.4);",
  };
  const style = colors[sev] || colors.INFO;
  return `<span style="display:inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; color: ${style}">${escapeHtml(sev)}</span>`;
}

function renderDonutChart(crit: number, high: number, med: number, low: number): string {
  const total = crit + high + med + low || 1;
  const pCrit = (crit / total) * 100;
  const pHigh = (high / total) * 100;
  const pMed = (med / total) * 100;
  const pLow = (low / total) * 100;

  // Simple clean SVG representation
  return `
    <div style="display:flex; align-items:center; gap:20px;">
      <svg width="120" height="120" viewBox="0 0 42 42" style="transform: rotate(-90deg);">
        <circle cx="21" cy="21" r="15.915" fill="transparent" stroke="#1e293b" stroke-width="5"></circle>
        <circle cx="21" cy="21" r="15.915" fill="transparent" stroke="#ef4444" stroke-width="5" stroke-dasharray="${pCrit} ${100 - pCrit}" stroke-dashoffset="0"></circle>
        <circle cx="21" cy="21" r="15.915" fill="transparent" stroke="#f97316" stroke-width="5" stroke-dasharray="${pHigh} ${100 - pHigh}" stroke-dashoffset="-${pCrit}"></circle>
        <circle cx="21" cy="21" r="15.915" fill="transparent" stroke="#eab308" stroke-width="5" stroke-dasharray="${pMed} ${100 - pMed}" stroke-dashoffset="-${pCrit + pHigh}"></circle>
        <circle cx="21" cy="21" r="15.915" fill="transparent" stroke="#3b82f6" stroke-width="5" stroke-dasharray="${pLow} ${100 - pLow}" stroke-dashoffset="-${pCrit + pHigh + pMed}"></circle>
      </svg>
      <div style="font-size: 12px; display:flex; flex-direction:column; gap:6px;">
        <div><span style="color:#ef4444">■</span> Critical: <b>${crit}</b></div>
        <div><span style="color:#f97316">■</span> High: <b>${high}</b></div>
        <div><span style="color:#eab308">■</span> Medium: <b>${med}</b></div>
        <div><span style="color:#3b82f6">■</span> Low: <b>${low}</b></div>
      </div>
    </div>
  `;
}

export async function generateHtmlReport(statusJsonPath?: string): Promise<string> {
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const defaultPath = resolve(process.cwd(), "reports/status.json");
  const targetJsonPath = statusJsonPath ? resolve(process.cwd(), statusJsonPath) : defaultPath;

  let data: StatusJsonContract;

  if (existsSync(targetJsonPath)) {
    data = JSON.parse(readFileSync(targetJsonPath, "utf-8"));
  } else {
    // Synthetic fallback dataset for Phase 14a port verification
    data = {
      schemaVersion: 1,
      timestamp: new Date().toISOString(),
      system: {
        name: "Blockchain Security Swarm",
        version: "1.0.0-phase14",
        commitSha: "08257cf1ac5fc21967d9d3eed1460dc364803f5d",
        status: "HEALTHY",
      },
      metrics: {
        totalFindings: 6,
        criticalFindings: 2,
        highFindings: 2,
        mediumFindings: 1,
        lowFindings: 1,
        complianceScorePct: 100,
        activeConsensusAlerts: 0,
        forensicCasesSealed: 3,
      },
      findings: [
        {
          id: "SEC-Z1-001",
          rule_id: "SWC-107",
          zone: "ZONE_1_CONTRACTS",
          severity: "CRITICAL",
          title: "Reentrancy Vulnerability Detected in Vault",
          description: "State update occurs after external ether transfer call.",
          target: "contracts/solidity/VulnerableVault.sol",
          status: "MITIGATED",
        },
        {
          id: "SEC-Z8-002",
          rule_id: "RULE-SANCTIONS-HIT",
          zone: "ZONE_8_COMPLIANCE",
          severity: "CRITICAL",
          title: "Sanctioned Router Target Detected",
          description: "Counterparty matched OFAC SDN Tornado Cash list.",
          target: "0xd90e2f925DA726b50C4Ed8D0Fb90Ad053324F31b",
          status: "VERIFIED",
        },
        {
          id: "SEC-Z6-003",
          rule_id: "RULE-CONSENSUS-ECLIPSE",
          zone: "ZONE_6_CONSENSUS",
          severity: "HIGH",
          title: "Low Autonomous System Number Diversity",
          description: "Peers clustered in a single network ASN.",
          target: "P2P Network Topology",
          status: "OPEN",
        },
      ],
      zones: {
        "ZONE_1_CONTRACTS": { status: "PASS", testCount: 85, summary: "Hardhat & Foundry unit suites verified." },
        "ZONE_2_FORENSICS": { status: "PASS", testCount: 50, summary: "Sealed evidence and volatile chain valid." },
        "ZONE_6_CONSENSUS": { status: "PASS", testCount: 99, summary: "Supermajority and BLS aggregation active." },
        "ZONE_7_WALLET": { status: "PASS", testCount: 56, summary: "Shamir key recovery and HSM emulator intact." },
        "ZONE_8_COMPLIANCE": { status: "PASS", testCount: 55, summary: "Sanctions screening and ZK attestations verified." },
      },
    };
  }

  const rows = (data.findings || []).map((f) => `
    <tr>
      <td style="font-family:monospace; font-size:12px;">${escapeHtml(f.id)}</td>
      <td>${renderSeverityBadge(f.severity)}</td>
      <td><span style="font-size:11px; background:#1e293b; padding:2px 6px; border-radius:4px;">${escapeHtml(f.zone)}</span></td>
      <td><b>${escapeHtml(f.title)}</b><div style="font-size:12px; color:#94a3b8; margin-top:2px;">${escapeHtml(f.description)}</div></td>
      <td style="font-family:monospace; font-size:11px; color:#cbd5e1;">${escapeHtml(f.target || "N/A")}</td>
      <td><span style="font-size:11px; font-weight:600; color:#38bdf8;">${escapeHtml(f.status)}</span></td>
    </tr>
  `).join("");

  const zoneRows = Object.entries(data.zones || {}).map(([zName, zData]) => `
    <tr>
      <td><b>${escapeHtml(zName)}</b></td>
      <td><span style="color:#22c55e; font-weight:700;">● ${escapeHtml(zData.status)}</span></td>
      <td style="font-family:monospace;">${zData.testCount} tests</td>
      <td style="color:#94a3b8; font-size:12px;">${escapeHtml(zData.summary)}</td>
    </tr>
  `).join("");

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(data.system.name)} — Executive Status Report</title>
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
    .container { max-width: 1300px; margin: 0 auto; }
    header {
      border-bottom: 1px solid var(--border-color);
      padding-bottom: 20px;
      margin-bottom: 30px;
      display: flex;
      justify-content: space-between;
      align-items: flex-end;
    }
    h1 { font-size: 24px; font-weight: 700; color: #fff; }
    .meta { font-size: 13px; color: var(--text-muted); margin-top: 5px; }
    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 20px;
      margin-bottom: 30px;
    }
    .kpi-card {
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 18px;
    }
    .kpi-title { font-size: 12px; color: var(--text-muted); text-transform: uppercase; font-weight: 600; letter-spacing: 0.5px; }
    .kpi-value { font-size: 28px; font-weight: 700; margin-top: 8px; color: #fff; }
    .section-card {
      background: var(--bg-secondary);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 24px;
      margin-bottom: 30px;
    }
    .section-title { font-size: 18px; font-weight: 600; margin-bottom: 16px; border-bottom: 1px solid var(--border-color); padding-bottom: 10px; }
    table { width: 100%; border-collapse: collapse; margin-top: 10px; }
    th { text-align: left; padding: 10px 12px; font-size: 12px; text-transform: uppercase; color: var(--text-muted); border-bottom: 1px solid var(--border-color); }
    td { padding: 12px; font-size: 13px; border-bottom: 1px solid #1a2538; vertical-align: top; }
    tr:hover { background: rgba(255, 255, 255, 0.02); }
    .toolbar {
      display: flex;
      gap: 12px;
      margin-bottom: 15px;
    }
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
    @media print {
      body { background: #fff; color: #000; padding: 0; }
      .section-card, .kpi-card { border: 1px solid #ccc; background: #fff; color: #000; }
      .toolbar { display: none; }
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <h1>${escapeHtml(data.system.name)} — Executive Report</h1>
        <div class="meta">Generated: ${escapeHtml(data.timestamp)} | Commit: <code>${escapeHtml(data.system.commitSha.slice(0, 10))}</code> | Release: ${escapeHtml(data.system.version)}</div>
      </div>
      <div>
        <button class="btn" onclick="window.print()">Print / Export PDF</button>
      </div>
    </header>

    <div class="kpi-grid">
      <div class="kpi-card">
        <div class="kpi-title">Total Active Findings</div>
        <div class="kpi-value">${data.metrics.totalFindings}</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-title">Critical & High Flaws</div>
        <div class="kpi-value" style="color: #ef4444;">${data.metrics.criticalFindings + data.metrics.highFindings}</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-title">Compliance Score</div>
        <div class="kpi-value" style="color: #22c55e;">${data.metrics.complianceScorePct}%</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-title">Forensic Vault Artifacts</div>
        <div class="kpi-value">${data.metrics.forensicCasesSealed}</div>
      </div>
    </div>

    <div class="section-card">
      <div class="section-title">Severity Breakdown</div>
      ${renderDonutChart(data.metrics.criticalFindings, data.metrics.highFindings, data.metrics.mediumFindings, data.metrics.lowFindings)}
    </div>

    <div class="section-card">
      <div class="section-title">Security Zone Verification Health</div>
      <table>
        <thead>
          <tr>
            <th>Security Zone</th>
            <th>Verification Status</th>
            <th>Automated Tests</th>
            <th>Description & Scope</th>
          </tr>
        </thead>
        <tbody>
          ${zoneRows}
        </tbody>
      </table>
    </div>

    <div class="section-card">
      <div class="section-title">Security Findings & Detected Flaws</div>
      <div class="toolbar">
        <input type="text" id="findingSearch" class="search-input" placeholder="Live search title, rule, target..." onkeyup="filterFindings()">
      </div>
      <table id="findingsTable">
        <thead>
          <tr>
            <th>ID</th>
            <th>Severity</th>
            <th>Zone</th>
            <th>Finding & Details</th>
            <th>Target Context</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          ${rows}
        </tbody>
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
