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
const TONE_HEX: Record<Tone, string> = {
  green: "#22c55e",
  red: "#ef4444",
  amber: "#eab308",
  gray: "#94a3b8",
  blue: "#38bdf8",
};
const TONE_STYLE: Record<Tone, string> = {
  green: "color:#22c55e; background:rgba(34,197,94,0.14); border:1px solid rgba(34,197,94,0.4);",
  red: "color:#ef4444; background:rgba(239,68,68,0.14); border:1px solid rgba(239,68,68,0.4);",
  amber: "color:#eab308; background:rgba(234,179,8,0.14); border:1px solid rgba(234,179,8,0.4);",
  gray: "color:#94a3b8; background:rgba(148,163,184,0.14); border:1px solid rgba(148,163,184,0.4);",
  blue: "color:#38bdf8; background:rgba(56,189,248,0.14); border:1px solid rgba(56,189,248,0.4);",
};

function badge(label: string, tone: Tone): string {
  return `<span class="badge" style="${TONE_STYLE[tone]}">${escapeHtml(label)}</span>`;
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

// Simple inline icon set — generic shapes only, no brand marks.
const ICON = {
  shield: `<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2l8 4v6c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V6l8-4z"/></svg>`,
  alert: `<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 9v4m0 4h.01M10.3 3.9L2.7 17a2 2 0 0 0 1.7 3h15.2a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/></svg>`,
  check: `<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 12l2 2 4-4M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0z"/></svg>`,
  lock: `<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2"><rect x="4" y="11" width="16" height="9" rx="2"/><path d="M8 11V7a4 4 0 1 1 8 0v4"/></svg>`,
  server: `<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="6" rx="1"/><rect x="3" y="14" width="18" height="6" rx="1"/><path d="M7 7h.01M7 17h.01"/></svg>`,
  flask: `<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 2v6l-5.5 9.5A2 2 0 0 0 5.2 21h13.6a2 2 0 0 0 1.7-3.5L15 8V2M9 2h6"/></svg>`,
  pulse: `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 12h4l2 8 4-16 2 8h6"/></svg>`,
  node: `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><circle cx="5" cy="12" r="2.4"/><circle cx="19" cy="6" r="2.4"/><circle cx="19" cy="18" r="2.4"/><path d="M7.2 11l9.8-4M7.2 13l9.8 4"/></svg>`,
  layers: `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3l9 5-9 5-9-5 9-5z"/><path d="M3 13l9 5 9-5"/></svg>`,
  cube: `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2l9 5v10l-9 5-9-5V7l9-5z"/><path d="M3 7l9 5 9-5M12 12v10"/></svg>`,
};

// --- Radial percentage gauge (SVG), used for the one KPI that is a % ---
function radialGauge(pct: number, color: string): string {
  const clamped = Math.max(0, Math.min(100, pct));
  const r = 19;
  const c = 2 * Math.PI * r;
  const dash = (clamped / 100) * c;
  return `
    <svg class="kpi-gauge" viewBox="0 0 48 48" width="48" height="48">
      <circle cx="24" cy="24" r="${r}" fill="none" stroke="rgba(255,255,255,0.08)" stroke-width="5"/>
      <circle cx="24" cy="24" r="${r}" fill="none" stroke="${color}" stroke-width="5"
        stroke-linecap="round" stroke-dasharray="${dash.toFixed(1)} ${c.toFixed(1)}"
        transform="rotate(-90 24 24)"/>
    </svg>`;
}

// --- Thin horizontal progress/agreement bar, used wherever a ratio needs showing ---
function miniBar(pct: number, color: string, trackColor = "rgba(255,255,255,0.08)"): string {
  const clamped = Math.max(0, Math.min(100, pct));
  return `<div class="mini-bar" style="background:${trackColor};"><div class="mini-bar-fill" style="width:${clamped}%; background:${color};"></div></div>`;
}

// --- Small multi-segment vote/tally bar, e.g. HALT/CLEAR/ABSTAIN counts ---
function voteStrip(segments: { label: string; value: number; color: string }[]): string {
  const total = segments.reduce((s, seg) => s + seg.value, 0) || 1;
  const bars = segments
    .filter((s) => s.value > 0)
    .map((s) => `<div style="flex:${s.value}; background:${s.color};" title="${escapeHtml(s.label)}: ${s.value}"></div>`)
    .join("");
  const legend = segments
    .map((s) => `<span class="vote-legend-item"><i style="background:${s.color};"></i>${escapeHtml(s.label)} ${s.value}</span>`)
    .join("");
  return `
    <div class="vote-strip">${bars || `<div style="flex:1; background:rgba(255,255,255,0.08);"></div>`}</div>
    <div class="vote-legend">${legend}</div>`;
}

// --- OWASP DSOMM: real evidence coverage, never a single collapsed number.
// Reads reports/scanners/dsomm.json directly (not via the v104 passthrough,
// which this report's other subsystem cards show is not currently populated)
// so this section always reflects what compute-dsomm-maturity.py actually
// computed this run, pass/fail per activity plus the honest "not_assessed"
// gap for everything no scanner here can speak to. ---
interface DsommActivity {
  dimension: string;
  subdimension: string;
  name: string;
  uuid: string;
  level: number;
  status: "pass" | "fail";
}
interface DsommSubdimension {
  dimension: string;
  level: number;
  assessed: number;
  total: number;
  coverage: number | null;
}
interface DsommResult {
  counts?: { activities_assessed?: number; activities_total?: number; subdimensions_with_signal?: number };
  detail?: string;
  subdimensions?: Record<string, DsommSubdimension>;
  activities?: DsommActivity[];
  model_totals?: Record<string, Record<string, number>>;
}

function renderDsommSection(dsomm: DsommResult | null): string {
  if (!dsomm) {
    return `
      <div id="dsomm" class="section-card">
        <div class="section-title"><span class="title-icon">${ICON.shield}</span>OWASP DSOMM Maturity</div>
        <div class="empty-note">No DSOMM evidence computed this run (compute-dsomm-maturity.py did not run).</div>
      </div>`;
  }

  const assessed = dsomm.counts?.activities_assessed ?? 0;
  const total = dsomm.counts?.activities_total ?? 0;
  const activitiesBySubdim = new Map<string, DsommActivity[]>();
  for (const a of dsomm.activities || []) {
    const list = activitiesBySubdim.get(a.subdimension) || [];
    list.push(a);
    activitiesBySubdim.set(a.subdimension, list);
  }

  const assessedCards = Object.entries(dsomm.subdimensions || {})
    .sort(([, a], [, b]) => (b.coverage ?? 0) - (a.coverage ?? 0))
    .map(([sub, data]) => {
      const pct = Math.round((data.coverage ?? 0) * 100);
      const acts = (activitiesBySubdim.get(sub) || [])
        .sort((a, b) => a.level - b.level)
        .map(
          (a) =>
            `<div class="infra-row" style="margin-top:4px;">
               <div class="infra-name" style="font-size:12px;">L${a.level} · ${escapeHtml(a.name)}</div>
               ${badge(a.status.toUpperCase(), a.status === "pass" ? "green" : "red")}
             </div>`
        )
        .join("");
      return `
        <div class="section-card" style="margin-bottom:10px;">
          <div class="sub-card-head">
            <div class="section-title" style="margin-bottom:0; font-size:14px;">${escapeHtml(sub)}</div>
            ${badge(`Claimed Level ${data.level}`, data.level > 0 ? "blue" : "amber")}
          </div>
          <div class="section-sub">${escapeHtml(data.dimension)} — ${data.assessed} of ${data.total} activities assessed (${pct}% coverage)</div>
          ${miniBar(pct, TONE_HEX.blue)}
          ${acts}
        </div>`;
    })
    .join("");

  // Dimensions/subdimensions with zero real signal -- the honest "we never
  // checked this" half, shown with equal visual weight, not buried.
  const assessedSubdimNames = new Set(Object.keys(dsomm.subdimensions || {}));
  const notAssessedRows: string[] = [];
  for (const [dim, subs] of Object.entries(dsomm.model_totals || {})) {
    for (const [sub, count] of Object.entries(subs)) {
      if (!assessedSubdimNames.has(sub)) {
        notAssessedRows.push(
          `<tr><td>${escapeHtml(dim)}</td><td>${escapeHtml(sub)}</td><td>${count}</td><td>${badge("NOT ASSESSED", "gray")}</td></tr>`
        );
      }
    }
  }

  return `
      <div id="dsomm" class="section-card">
        <div class="section-title"><span class="title-icon">${ICON.shield}</span>OWASP DSOMM Maturity — Real Evidence Coverage</div>
        <div class="section-sub">${escapeHtml(
          dsomm.detail ||
            `${assessed} of ${total} official DSOMM v5.0.2 activities have automated evidence this run.`
        )} This is deliberately not one score: a single number here would hide exactly how partial this coverage is.</div>

        <p style="font-size:13px; color:#cbd5e1; margin-top:14px;">Assessed this run — real pass/fail evidence, with the subdimension's claimed level capped below any failed activity:</p>
        ${assessedCards || `<div class="empty-note">No activities assessed this run.</div>`}

        <p style="font-size:13px; color:#cbd5e1; margin-top:18px;">Not assessed — no tooling in this pipeline can check these; they require manual or organizational evidence (e.g. security champions programs, training records, threat-modeling process, access reviews):</p>
        <div class="table-scroll"><table>
          <thead><tr><th>Dimension</th><th>Subdimension</th><th>Activities</th><th>Status</th></tr></thead>
          <tbody>${notAssessedRows.join("") || `<tr><td colspan="4" class="empty-note">Everything in the model was assessed.</td></tr>`}</tbody>
        </table></div>
      </div>`;
}

function kpiCard(icon: string, title: string, value: string | number, sub?: string, color = "#fff", flag?: string, gaugePct?: number): string {
  const numericPct = gaugePct !== undefined ? gaugePct : null;
  return `
    <div class="kpi-card" style="--kpi-accent:${color};">
      <div class="kpi-top">
        <div class="kpi-icon">${icon}</div>
        ${numericPct !== null ? radialGauge(numericPct, color) : ""}
      </div>
      <div class="kpi-title">${escapeHtml(title)}${flag ? `<span class="cumulative-flag">${escapeHtml(flag)}</span>` : ""}</div>
      <div class="kpi-value" style="color:${color};">${value}</div>
      ${sub ? `<div class="kpi-sub">${escapeHtml(sub)}</div>` : ""}
    </div>`;
}

function renderTrendSparkline(trend: StatusJsonOutput["trend"]): string {
  if (!trend || trend.length === 0) {
    return `<div class="empty-note">No run history yet — this view was added on ${new Date().toISOString().slice(0, 10)} and only tracks runs from here forward (reports/run-history.jsonl). It is not backfilled.</div>`;
  }
  const rows = trend
    .slice()
    .reverse()
    .map(
      (t) => `
    <tr>
      <td class="mono">${escapeHtml(t.timestamp)}</td>
      <td class="mono">${escapeHtml(t.commitSha.slice(0, 10))}</td>
      <td class="mono">${escapeHtml(t.target.split("/").pop() || t.target)}</td>
      <td>${badge(t.health, toneForGateStatus(t.health === "OK" ? "ok" : "error"))}</td>
      <td>${badge(t.verdict, toneForVerdict(t.verdict))}</td>
      <td class="mono">${t.criticalFindings} crit / ${t.highFindings} high / ${t.totalFindings} total</td>
    </tr>`
    )
    .join("");
  return `
    <p class="section-sub">Last ${trend.length} run(s) recorded in <code>reports/run-history.jsonl</code> since this view was added — a real, growing history, never backfilled with invented past runs.</p>
    <div class="table-scroll"><table>
      <thead><tr><th>Run Timestamp</th><th>Commit</th><th>Target</th><th>Health</th><th>Verdict</th><th>Findings</th></tr></thead>
      <tbody>${rows}</tbody>
    </table></div>`;
}

function renderSarDraftSection(): string {
  const p = resolve(process.cwd(), "reports/scanners/sar-draft.json");
  if (!existsSync(p)) {
    return `<div id="sar-draft" class="section-card"><div class="section-title"><span class="title-icon">${ICON.shield}</span>Draft SAR (Suspicious Activity Report)</div><div class="empty-note">Not run this cycle, or this run's verdict was not HALT (no suspicious-activity case).</div></div>`;
  }
  const r = JSON.parse(readFileSync(p, "utf-8"));
  const draftPath = resolve(process.cwd(), "reports/sar-draft-report.json");
  const draft = existsSync(draftPath) ? JSON.parse(readFileSync(draftPath, "utf-8")) : null;
  const typologyRows = (draft?.typologies_detected || [])
    .map((t: string) => `<tr><td class="mono">${escapeHtml(t)}</td></tr>`)
    .join("");
  return `
    <div id="sar-draft" class="section-card">
      <div class="section-title"><span class="title-icon">${ICON.shield}</span>Draft SAR (Suspicious Activity Report)</div>
      <div class="section-sub">Triggered only when this run's real pipeline verdict was HALT, the same signal Zone 4's Jira/TheHive incident response keys off (<code>src/compliance/sar_generator.py</code>). Stays ${escapeHtml(draft?.status || "DRAFT_PENDING_REVIEW")} / ${escapeHtml(draft?.filing_channel || "LOCAL_STAGING_ONLY")} — nothing here files externally without human review.</div>
      <div class="infra-row">
        <div class="infra-name"><span class="infra-dot" style="color:${r.status === "ok" ? TONE_HEX.green : TONE_HEX.red};"></span>${escapeHtml(draft?.report_id || "")}</div>
        ${badge((r.status || "unknown").toUpperCase(), toneForGateStatus(r.status))}
      </div>
      <div class="table-scroll"><table>
        <thead><tr><th>Typology Detected</th></tr></thead>
        <tbody>${typologyRows || `<tr><td class="empty-note">No typologies.</td></tr>`}</tbody>
      </table></div>
      <div class="infra-detail" style="text-align:left; max-width:100%;">${escapeHtml(r.detail || "")}</div>
    </div>`;
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
  const dsommPath = resolve(process.cwd(), "reports/scanners/dsomm.json");
  const dsommResult: DsommResult | null = existsSync(dsommPath)
    ? JSON.parse(readFileSync(dsommPath, "utf-8"))
    : null;
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
      <td class="mono dim">${escapeHtml(g.tool || "")}</td>
      <td>${badge((g.policy || "informational").toUpperCase(), g.policy === "required" ? "blue" : "gray")}</td>
      <td>${badge((g.status || "unknown").toUpperCase(), toneForGateStatus(g.status))}</td>
      <td class="dim detail-cell">${escapeHtml(g.detail || "")}${g.counts ? ` <span class="mono dim2">${escapeHtml(JSON.stringify(g.counts))}</span>` : ""}</td>
    </tr>`
    )
    .join("");

  // --- Gate pass/fail counts by policy, for the bar chart ---
  const requiredGates = (data.gates || []).filter((g) => g.policy === "required");
  const infoGates = (data.gates || []).filter((g) => g.policy !== "required");
  const requiredOk = requiredGates.filter((g) => g.status === "ok").length;
  const requiredBad = requiredGates.length - requiredOk;
  const infoOk = infoGates.filter((g) => g.status === "ok").length;
  const infoBad = infoGates.length - infoOk;

  // --- Findings by zone, for the bar chart ---
  const zoneCounts: Record<string, number> = {};
  for (const f of data.findings || []) {
    const z = f.zone || "UNSPECIFIED";
    zoneCounts[z] = (zoneCounts[z] || 0) + 1;
  }
  const zoneLabels = Object.keys(zoneCounts).sort();
  const zoneValues = zoneLabels.map((z) => zoneCounts[z]);

  // --- Master findings table (searchable) ---
  const findingRows = (data.findings || [])
    .map(
      (f) => `
    <tr>
      <td class="mono">${escapeHtml(f.id)}</td>
      <td>${badge(f.severity, toneForSeverity(f.severity))}</td>
      <td><span class="zone-chip">${escapeHtml(f.zone)}</span></td>
      <td class="finding-cell"><b>${escapeHtml(f.title)}</b><div class="dim" style="font-size:12px; margin-top:2px;">${escapeHtml(f.description)}</div></td>
      <td class="mono dim2 detail-cell">${escapeHtml(f.target || "N/A")}</td>
      <td>${badge(f.status, toneForFindingStatus(f.status))}</td>
    </tr>`
    )
    .join("");

  const walletRows = (data.walletAuditFindings || [])
    .map(
      (w) => `
    <tr>
      <td class="mono">${escapeHtml(w.findingId)}</td>
      <td><b>${escapeHtml(w.vulnerabilityClass)}</b></td>
      <td>${badge(w.status, toneForFindingStatus(w.status))}</td>
    </tr>`
    )
    .join("");

  const forensicRows = (data.forensicCases || [])
    .map(
      (c) => `
    <tr>
      <td class="mono">${escapeHtml(c.caseId)}</td>
      <td class="mono detail-cell" style="color:#93c5fd;">${escapeHtml(c.targetAddress || "—")}</td>
      <td class="mono">${c.sealedArtifactsCount} file(s)</td>
      <td>${badge(c.integrityVerified ? "CHAIN VERIFIED" : "UNVERIFIED", c.integrityVerified ? "green" : "red")}</td>
      <td class="dim detail-cell">${escapeHtml(c.redactedSummary)}</td>
    </tr>`
    )
    .join("");

  const complianceRows = (data.complianceRegister || [])
    .map(
      (cr) => `
    <tr>
      <td class="mono dim2 detail-cell">${escapeHtml(cr.entityAddress)}</td>
      <td>${badge(cr.sanctionMatch ? "SDN MATCH" : "CLEAN", cr.sanctionMatch ? "red" : "green")}</td>
      <td>${badge(cr.riskTier, cr.sanctionMatch ? "red" : "green")}</td>
      <td class="dim detail-cell">${escapeHtml(cr.reason || "")}</td>
    </tr>`
    )
    .join("");

  const incidentRows = (data.incidents || [])
    .map(
      (i) => `
    <tr>
      <td class="mono">${escapeHtml(i.id)}</td>
      <td class="finding-cell">${escapeHtml(i.title)}</td>
      <td>${badge(i.severity, toneForSeverity(i.severity))}</td>
      <td>${badge(i.status, toneForFindingStatus(i.status))}</td>
      <td class="mono dim2">${escapeHtml(i.createdAt)}</td>
    </tr>`
    )
    .join("");

  const consensusRows = (data.consensusAlerts || [])
    .map(
      (a) => `
    <tr>
      <td class="mono">${escapeHtml(a.alertId)}</td>
      <td class="finding-cell">${escapeHtml(a.anomalyType)}</td>
      <td>${badge(a.severity, toneForSeverity(a.severity))}</td>
      <td>${badge(a.avsQuorumConfirmed ? "QUORUM CONFIRMED" : "NOT CONFIRMED", a.avsQuorumConfirmed ? "red" : "green")}</td>
      <td class="mono dim2">${escapeHtml(a.timestamp)}</td>
    </tr>`
    )
    .join("");

  // --- Trend chart data (real history only, never backfilled) ---
  const trendSeq = (data.trend || []).slice().reverse();
  const trendLabels = trendSeq.map((t) => t.timestamp.slice(5, 16));
  const trendCritHigh = trendSeq.map((t) => t.criticalFindings + t.highFindings);
  const trendTotal = trendSeq.map((t) => t.totalFindings);

  const crit = data.metrics.criticalFindings;
  const high = data.metrics.highFindings;
  const med = data.metrics.mediumFindings;
  const low = data.metrics.lowFindings;

  // --- AVS Consensus visual data ---
  const avs = v104.avs_consensus;
  const avsAgreementPct = avs ? parseFloat(String(avs.agreement_ratio).replace("%", "")) || 0 : 0;
  const avsIsHalt = avs?.decision?.includes("EXPLOIT") || avs?.decision?.includes("HALT");
  const avsNodeCount = avs?.ports?.length || 0;
  const avsConfirmedCount = avsIsHalt ? avsNodeCount : 0;

  // --- LangGraph swarm vote data ---
  const swarm = v104.langgraph_swarm;
  const swarmVotes = swarm?.votes || {};
  const swarmHalt = Number(swarmVotes.halt || 0);
  const swarmClear = Number(swarmVotes.clear || 0);
  const swarmAbstain = Number(swarmVotes.abstain || 0);
  const swarmNotRun = Number(swarmVotes.not_run || 0);

  // --- Infra status for mini indicator dots ---
  const vaultOk = v104.hashicorp_vault?.status === "ok";
  const k3sOk = v104.k3s_kubernetes?.status === "ok";
  const openscapStatus = v104.openscap?.status;

  let html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(data.system.name)} — Executive Security Report</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
  <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
  <style>
    :root {
      --bg-primary: #0a0e16;
      --bg-secondary: #10151f;
      --bg-card: #141b29;
      --bg-card-alt: #121826;
      --border-color: #232e42;
      --text-main: #f1f5f9;
      --text-muted: #8b98ab;
      --accent: #38bdf8;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    html { scroll-behavior: smooth; }
    body {
      background: var(--bg-primary);
      color: var(--text-main);
      font-family: 'Inter', system-ui, -apple-system, sans-serif;
      line-height: 1.5;
      overflow-x: hidden;
    }
    .mono { font-family: 'JetBrains Mono', monospace; word-break: break-all; }
    .dim { color: var(--text-muted); }
    .dim2 { color: #64748b; }
    .layout { display: grid; grid-template-columns: 220px 1fr; min-height: 100vh; max-width: 100%; }
    nav.sidebar {
      position: sticky; top: 0; height: 100vh; overflow-y: auto;
      background: var(--bg-secondary); border-right: 1px solid var(--border-color);
      padding: 24px 16px;
    }
    nav.sidebar .brand { font-weight: 800; font-size: 15px; margin-bottom: 4px; color: #fff; }
    nav.sidebar .brand-sub { font-size: 11px; color: var(--text-muted); margin-bottom: 20px; }
    nav.sidebar a {
      display: flex; align-items: center; gap: 8px; padding: 8px 10px; border-radius: 6px; font-size: 13px;
      color: var(--text-muted); text-decoration: none; margin-bottom: 2px;
      border-left: 2px solid transparent;
    }
    nav.sidebar a:hover { background: rgba(255,255,255,0.04); color: #fff; border-left-color: var(--accent); }
    main { padding: 32px 40px; max-width: 1400px; width: 100%; min-width: 0; overflow-x: hidden; }
    header.top {
      border-bottom: 1px solid var(--border-color);
      padding-bottom: 20px; margin-bottom: 24px;
      display: flex; justify-content: space-between; align-items: flex-end; flex-wrap: wrap; gap: 12px;
    }
    h1 { font-size: 23px; font-weight: 800; color: #fff; letter-spacing: -0.3px; }
    .meta { font-size: 12.5px; color: var(--text-muted); margin-top: 6px; }
    .meta code { background: rgba(255,255,255,0.06); padding: 1px 6px; border-radius: 4px; }
    .btn {
      background: var(--bg-card); border: 1px solid var(--border-color); color: var(--text-main);
      padding: 9px 16px; border-radius: 7px; font-size: 13px; cursor: pointer; font-weight: 500;
    }
    .btn:hover { background: #1b2436; border-color: #334155; }

    /* --- Verdict banner: bigger, with an icon chip and a severity glow for HALT --- */
    .verdict-banner {
      display: flex; align-items: center; gap: 20px; flex-wrap: wrap;
      padding: 24px 28px; border-radius: 14px; margin-bottom: 28px;
      background: linear-gradient(135deg, var(--bg-card), var(--bg-secondary));
      border: 1px solid var(--border-color);
      position: relative; overflow: hidden;
    }
    .verdict-banner.tone-red { border-color: rgba(239,68,68,0.45); box-shadow: 0 0 0 1px rgba(239,68,68,0.12), 0 18px 48px -24px rgba(239,68,68,0.45); }
    .verdict-banner.tone-green { border-color: rgba(34,197,94,0.4); box-shadow: 0 0 0 1px rgba(34,197,94,0.1), 0 18px 48px -24px rgba(34,197,94,0.4); }
    .verdict-banner.tone-amber { border-color: rgba(234,179,8,0.4); box-shadow: 0 0 0 1px rgba(234,179,8,0.1), 0 18px 48px -24px rgba(234,179,8,0.4); }
    .verdict-icons { display: flex; gap: 12px; flex-wrap: wrap; }
    .verdict-chip {
      display: flex; align-items: center; gap: 10px;
      font-size: 17px; padding: 10px 18px 10px 14px; border-radius: 10px; font-weight: 800; letter-spacing: 0.4px;
      white-space: nowrap;
    }
    .verdict-chip .chip-icon { display: flex; align-items: center; justify-content: center; width: 26px; height: 26px; border-radius: 50%; background: rgba(255,255,255,0.12); flex-shrink: 0; }
    .verdict-chip .chip-icon svg { width: 15px; height: 15px; }
    .verdict-banner p { font-size: 13.5px; color: #cbd5e1; max-width: 820px; overflow-wrap: anywhere; }
    @keyframes pulseRing { 0% { box-shadow: 0 0 0 0 rgba(239,68,68,0.5); } 70% { box-shadow: 0 0 0 10px rgba(239,68,68,0); } 100% { box-shadow: 0 0 0 0 rgba(239,68,68,0); } }
    .verdict-chip.pulse { animation: pulseRing 2.4s ease-out infinite; }

    /* --- KPI cards: icon + optional radial gauge + accent bar --- */
    .kpi-grid {
      display: grid; grid-template-columns: repeat(auto-fit, minmax(195px, 1fr));
      gap: 14px; margin-bottom: 28px;
    }
    .kpi-card {
      background: linear-gradient(160deg, var(--bg-card), var(--bg-card-alt));
      border: 1px solid var(--border-color); border-radius: 12px;
      padding: 16px 18px; position: relative; transition: border-color 0.15s, transform 0.15s;
      overflow: hidden; min-width: 0;
    }
    .kpi-card::before {
      content: ""; position: absolute; top: 0; left: 0; right: 0; height: 3px;
      background: var(--kpi-accent, var(--accent)); opacity: 0.85;
    }
    .kpi-card:hover { border-color: #334155; transform: translateY(-1px); }
    .kpi-top { display: flex; align-items: center; justify-content: space-between; margin-bottom: 10px; }
    .kpi-icon {
      color: var(--kpi-accent, var(--accent)); display: flex; align-items: center; justify-content: center;
      width: 34px; height: 34px; border-radius: 9px; background: rgba(255,255,255,0.07);
      border: 1px solid rgba(255,255,255,0.08);
    }
    .kpi-gauge { flex-shrink: 0; }
    .kpi-title { font-size: 10.5px; color: var(--text-muted); text-transform: uppercase; font-weight: 700; letter-spacing: 0.5px; }
    .kpi-value { font-size: 27px; font-weight: 800; margin-top: 6px; color: #fff; line-height: 1.1; word-break: break-word; }
    .kpi-sub { font-size: 10.5px; color: var(--text-muted); margin-top: 4px; }

    .section-card {
      background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 12px;
      padding: 22px; margin-bottom: 22px; scroll-margin-top: 20px; min-width: 0; overflow: hidden;
    }
    .section-title { font-size: 15px; font-weight: 700; margin-bottom: 6px; display: flex; align-items: center; gap: 8px; }
    .section-title .title-icon { color: var(--accent); display: flex; align-items: center; }
    .section-sub { font-size: 12px; color: var(--text-muted); margin-bottom: 14px; }
    .table-scroll { overflow-x: auto; max-width: 100%; }
    table { width: 100%; border-collapse: collapse; margin-top: 6px; min-width: 560px; }
    th { text-align: left; padding: 10px 12px; font-size: 10.5px; text-transform: uppercase; letter-spacing: 0.4px; color: var(--text-muted); border-bottom: 1px solid var(--border-color); white-space: nowrap; }
    td { padding: 11px 12px; font-size: 13px; border-bottom: 1px solid #1a2334; vertical-align: top; overflow-wrap: anywhere; }
    .detail-cell { max-width: 360px; }
    .finding-cell { max-width: 420px; }
    tr:hover td { background: rgba(255,255,255,0.015); }
    .badge { display:inline-block; padding:2px 9px; border-radius:5px; font-size:10.5px; font-weight:700; letter-spacing:0.2px; white-space: nowrap; }
    .zone-chip { font-size: 10.5px; background: #1c2538; padding: 3px 8px; border-radius: 5px; color: #93c5fd; white-space: nowrap; }
    .cumulative-flag { font-size: 9.5px; color: #eab308; background: rgba(234,179,8,0.12); border: 1px solid rgba(234,179,8,0.4); padding: 1px 6px; border-radius: 4px; margin-left: 6px; }
    .toolbar { display: flex; gap: 12px; margin-bottom: 14px; }
    .search-input {
      background: var(--bg-primary); border: 1px solid var(--border-color); border-radius: 7px;
      color: #fff; padding: 9px 14px; font-size: 13px; width: 320px; max-width: 100%;
    }
    .grid-2 { display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 18px; }
    .chart-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(340px, 1fr)); gap: 18px; margin-bottom: 22px; }
    .chart-box { position: relative; height: 240px; max-width: 100%; }
    .empty-note { font-size: 12px; color: var(--text-muted); padding: 10px 0; }
    details.collapsible summary {
      cursor: pointer; font-size: 15px; font-weight: 700; list-style: none;
      display: flex; align-items: center; gap: 8px; padding-bottom: 6px;
    }
    details.collapsible summary::-webkit-details-marker { display: none; }
    details.collapsible summary::before { content: "▸"; display: inline-block; transition: transform 0.15s; color: var(--accent); }
    details.collapsible[open] summary::before { transform: rotate(90deg); }

    /* --- Subsystem cards (AVS / Swarm / Infra / OWASP): richer visual treatment --- */
    .sub-card-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; margin-bottom: 14px; }
    .sub-card-head .decision-pill { display: flex; align-items: center; gap: 8px; }
    .stat-row { display: flex; align-items: baseline; gap: 10px; margin: 4px 0 10px; flex-wrap: wrap; }
    .stat-big { font-size: 26px; font-weight: 800; color: #fff; }
    .stat-label { font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.4px; }
    .mini-bar { width: 100%; height: 8px; border-radius: 99px; overflow: hidden; margin: 6px 0 4px; }
    .mini-bar-fill { height: 100%; border-radius: 99px; transition: width 0.4s ease; }
    .node-row { display: flex; gap: 8px; margin: 10px 0; flex-wrap: wrap; }
    .node-chip {
      display: flex; align-items: center; gap: 6px; font-size: 11.5px; font-weight: 600;
      padding: 5px 10px; border-radius: 99px; background: rgba(255,255,255,0.04);
      border: 1px solid var(--border-color);
    }
    .node-chip .dot { width: 7px; height: 7px; border-radius: 50%; flex-shrink: 0; }
    .vote-strip { display: flex; width: 100%; height: 14px; border-radius: 7px; overflow: hidden; margin: 10px 0 8px; background: rgba(255,255,255,0.05); }
    .vote-strip > div { transition: flex 0.4s ease; }
    .vote-legend { display: flex; gap: 14px; flex-wrap: wrap; font-size: 11.5px; color: var(--text-muted); }
    .vote-legend-item { display: flex; align-items: center; gap: 6px; }
    .vote-legend-item i { width: 9px; height: 9px; border-radius: 3px; display: inline-block; }
    .infra-row { display: flex; align-items: center; justify-content: space-between; gap: 10px; padding: 10px 0; border-bottom: 1px solid #1a2334; }
    .infra-row:last-child { border-bottom: none; }
    .infra-name { display: flex; align-items: center; gap: 10px; font-size: 13px; font-weight: 600; min-width: 0; }
    .infra-dot { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; box-shadow: 0 0 0 3px currentColor; opacity: 0.9; }
    .infra-detail { font-size: 11.5px; color: var(--text-muted); overflow-wrap: anywhere; text-align: right; max-width: 55%; }
    .owasp-tags { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 10px; }
    .owasp-tag { font-size: 11.5px; font-weight: 600; padding: 6px 12px; border-radius: 8px; background: rgba(239,68,68,0.12); border: 1px solid rgba(239,68,68,0.35); color: #fca5a5; }

    @media print {
      body { background: #fff; color: #000; }
      nav.sidebar, .toolbar, .btn { display: none !important; }
      .layout { grid-template-columns: 1fr; }
      main { padding: 0; }
      .section-card, .kpi-card, .verdict-banner { border: 1px solid #ccc; background: #fff; color: #000; }
      .chart-box { height: 180px; }
      .chart-box canvas { max-height: 180px; }
      .chart-grid { grid-template-columns: repeat(2, 1fr); }
      .kpi-grid { grid-template-columns: repeat(3, 1fr); }
      .grid-2 { grid-template-columns: repeat(2, 1fr); }
    }
    @media (max-width: 900px) {
      .layout { grid-template-columns: 1fr; }
      nav.sidebar { position: static; height: auto; }
      main { padding: 20px; }
    }
  </style>
</head>
<body>
  <div class="layout">
    <nav class="sidebar">
      <div class="brand">${escapeHtml(data.system.name)}</div>
      <div class="brand-sub">Executive Security Report</div>
      <a href="#summary">Executive Summary</a>
      <a href="#charts">Visual Overview</a>
      <a href="#gates">Gate-by-Gate Status</a>
      <a href="#subsystems">AVS / Swarm / Infra</a>
      <a href="#sar-draft">Draft SAR</a>
      <a href="#wallet">Wallet Simulation</a>
      <a href="#forensics">Forensics &amp; Custody</a>
      <a href="#incidents">Incident Response</a>
      <a href="#compliance">OFAC Compliance</a>
      <a href="#trend">Run History</a>
      <a href="#findings">Findings Register</a>
    </nav>
    <main>
      <header class="top">
        <div>
          <h1>${escapeHtml(data.system.name)} — Executive Security Report</h1>
          <div class="meta">Generated: ${escapeHtml(data.timestamp)} &nbsp;|&nbsp; Commit: <code>${escapeHtml(data.system.commitSha.slice(0, 10))}</code> &nbsp;|&nbsp; Release: ${escapeHtml(data.system.version)} &nbsp;|&nbsp; Target: <code>${escapeHtml(targetName)}</code></div>
        </div>
        <button class="btn" onclick="window.print()">Print / Export PDF</button>
      </header>

      <div id="summary" class="verdict-banner tone-${toneForVerdict(verdict)}">
        <div class="verdict-icons">
          <div class="verdict-chip ${verdict === "HALT" ? "pulse" : ""}" style="${TONE_STYLE[toneForVerdict(verdict)]}">
            <span class="chip-icon">${verdict === "HALT" ? ICON.alert : verdict === "PASS" ? ICON.check : ICON.shield}</span>${escapeHtml(verdict)}
          </div>
          <div class="verdict-chip" style="${TONE_STYLE[toneForGateStatus(healthOk ? "ok" : "error")]}">
            <span class="chip-icon">${healthOk ? ICON.check : ICON.alert}</span>HEALTH: ${escapeHtml(data.pipeline?.health || "UNKNOWN")}
          </div>
        </div>
        <p>${execSummary}</p>
      </div>

      <div class="kpi-grid">
        ${kpiCard(ICON.alert, "Total Findings (this run)", data.metrics.totalFindings, undefined, "#38bdf8")}
        ${kpiCard(ICON.shield, "Critical &amp; High (this run)", data.metrics.criticalFindings + data.metrics.highFindings, undefined, "#ef4444")}
        ${kpiCard(ICON.check, "Required Gates Passing", `${data.metrics.complianceScorePct}%`, undefined, data.metrics.complianceScorePct === 100 ? "#22c55e" : "#eab308", undefined, data.metrics.complianceScorePct)}
        ${kpiCard(ICON.server, "Active Consensus Alerts", data.metrics.activeConsensusAlerts, undefined, "#f97316")}
        ${kpiCard(ICON.lock, "Forensic Cases Sealed (this run)", data.metrics.forensicCasesSealed, undefined, "#a78bfa")}
        ${kpiCard(ICON.flask, "DefectDojo Unique Flaws", ddj?.active_unique_findings ?? "N/A", "Across all historical runs — not this run's count.", "#38bdf8", "CUMULATIVE")}
      </div>

      <div id="charts" class="section-card">
        <div class="section-title"><span class="title-icon">${ICON.pulse}</span>Visual Overview</div>
        <div class="section-sub">Every chart below is drawn from this run's real fields — nothing is estimated or templated.</div>
        <div class="chart-grid">
          <div><div class="dim" style="font-size:12px; margin-bottom:6px;">Severity Breakdown</div><div class="chart-box"><canvas id="chartSeverity"></canvas></div></div>
          <div><div class="dim" style="font-size:12px; margin-bottom:6px;">Findings by Zone</div><div class="chart-box"><canvas id="chartZone"></canvas></div></div>
          <div><div class="dim" style="font-size:12px; margin-bottom:6px;">Gate Status by Policy</div><div class="chart-box"><canvas id="chartGates"></canvas></div></div>
          <div><div class="dim" style="font-size:12px; margin-bottom:6px;">Run History Trend</div><div class="chart-box"><canvas id="chartTrend"></canvas></div></div>
        </div>
      </div>

      <div id="gates" class="section-card">
        <div class="section-title"><span class="title-icon">${ICON.layers}</span>Gate-by-Gate Status (this run)</div>
        <div class="section-sub">Every real scanner/consensus result this pipeline run produced under <code>reports/scanners/*.json</code>. BLUE policy = required for the ship/no-ship verdict; GRAY = informational signal only.</div>
        <div class="table-scroll"><table>
          <thead><tr><th>Gate</th><th>Tool</th><th>Policy</th><th>Status</th><th>Detail</th></tr></thead>
          <tbody>${gateRows || `<tr><td colspan="5" class="empty-note">No gate results found for this run.</td></tr>`}</tbody>
        </table></div>
      </div>

      <div id="subsystems" class="grid-2">
        <div class="section-card">
          <div class="sub-card-head">
            <div class="section-title" style="margin-bottom:0;"><span class="title-icon">${ICON.node}</span>AVS Consensus (3-Node Live EVM Execution)</div>
          </div>
          <div class="section-sub">${v104.avs_consensus ? `${escapeHtml(v104.avs_consensus.protocol)} — ${escapeHtml(v104.avs_consensus.topology)}` : "No AVS consensus result this run."}</div>
          ${
            avs
              ? `
          <div class="stat-row">
            <span class="stat-big">${escapeHtml(String(avs.agreement_ratio))}</span>
            <span class="stat-label">Node Agreement</span>
            ${badge(avs.decision, avsIsHalt ? "red" : "green")}
          </div>
          ${miniBar(avsAgreementPct, avsIsHalt ? TONE_HEX.red : TONE_HEX.green)}
          <div class="node-row">
            ${(avs.ports || [])
              .map(
                (p: number, i: number) =>
                  `<span class="node-chip"><span class="dot" style="background:${i < avsConfirmedCount ? TONE_HEX.red : TONE_HEX.green};"></span>Node :${escapeHtml(String(p))} ${i < avsConfirmedCount ? "EXPLOIT" : "CLEAN"}</span>`
              )
              .join("")}
          </div>`
              : `<div class="empty-note">No AVS consensus result this run.</div>`
          }
        </div>
        <div class="section-card">
          <div class="sub-card-head">
            <div class="section-title" style="margin-bottom:0;"><span class="title-icon">${ICON.layers}</span>LangGraph 7-Agent Swarm</div>
          </div>
          <div class="section-sub">${swarm ? `${swarm.agents_count} agents via ${escapeHtml(swarm.framework)}` : "No swarm result this run."}</div>
          ${
            swarm
              ? `
          <div class="stat-row">
            ${badge(swarm.decision, swarm.decision === "HALT_CONFIRMED" ? "red" : "green")}
          </div>
          ${voteStrip([
            { label: "HALT", value: swarmHalt, color: TONE_HEX.red },
            { label: "CLEAR", value: swarmClear, color: TONE_HEX.green },
            { label: "ABSTAIN", value: swarmAbstain, color: TONE_HEX.amber },
            { label: "NOT RUN", value: swarmNotRun, color: TONE_HEX.gray },
          ])}`
              : ""
          }
        </div>
        <div class="section-card">
          <div class="section-title"><span class="title-icon">${ICON.cube}</span>Infrastructure: Vault &amp; Kubernetes</div>
          <div class="infra-row">
            <div class="infra-name"><span class="infra-dot" style="color:${vaultOk ? TONE_HEX.green : TONE_HEX.red};"></span>HashiCorp Vault (Transit)</div>
            ${v104.hashicorp_vault ? badge(v104.hashicorp_vault.status, toneForGateStatus(v104.hashicorp_vault.status)) : badge("NOT RUN", "gray")}
          </div>
          <div class="infra-detail" style="text-align:left; max-width:100%; margin-bottom:6px;">${escapeHtml(v104.hashicorp_vault?.detail || "")}</div>
          <div class="infra-row">
            <div class="infra-name"><span class="infra-dot" style="color:${k3sOk ? TONE_HEX.green : TONE_HEX.red};"></span>K3s Kubernetes</div>
            ${v104.k3s_kubernetes ? badge(v104.k3s_kubernetes.status, toneForGateStatus(v104.k3s_kubernetes.status)) : badge("NOT RUN", "gray")}
          </div>
          <div class="infra-detail" style="text-align:left; max-width:100%;">${escapeHtml(v104.k3s_kubernetes?.node || "")} ${escapeHtml(v104.k3s_kubernetes?.version || "")} ${escapeHtml(v104.k3s_kubernetes?.detail || "")}</div>
        </div>
        <div class="section-card">
          <div class="section-title"><span class="title-icon">${ICON.shield}</span>OWASP Smart Contract Coverage</div>
          <p style="font-size:13px; color:#cbd5e1;">Categories actually triggered this run:</p>
          <div class="owasp-tags">
            ${(v104.owasp_sc_top_10 || "none")
              .split(",")
              .map((c: string) => `<span class="owasp-tag">${escapeHtml(c.trim())}</span>`)
              .join("")}
          </div>
          <div class="infra-row" style="margin-top:14px;">
            <div class="infra-name"><span class="infra-dot" style="color:${openscapStatus === "AUDITED_ACTIVE" ? TONE_HEX.green : openscapStatus === "ERROR" ? TONE_HEX.red : TONE_HEX.amber};"></span>OpenSCAP</div>
            ${v104.openscap ? badge(v104.openscap.status, toneForGateStatus(v104.openscap.status === "AUDITED_ACTIVE" ? "ok" : v104.openscap.status === "ERROR" ? "error" : "not_run")) : badge("NOT RUN", "gray")}
          </div>
          <div class="infra-detail" style="text-align:left; max-width:100%;">${escapeHtml(v104.openscap?.standard || "")}</div>
        </div>
      </div>

      ${renderDsommSection(dsommResult)}
      ${renderSarDraftSection()}

      <div id="wallet" class="section-card">
        <details class="collapsible" open>
          <summary>Wallet Pre-Sign Simulation</summary>
          <div class="table-scroll"><table>
            <thead><tr><th>Audit ID</th><th>Check</th><th>Status</th></tr></thead>
            <tbody>${walletRows || `<tr><td colspan="3" class="empty-note">No pre-sign simulation result this run.</td></tr>`}</tbody>
          </table></div>
        </details>
      </div>

      <div id="forensics" class="section-card">
        <div class="section-title"><span class="title-icon">${ICON.lock}</span>Forensics &amp; Chain of Custody</div>
        <div class="table-scroll"><table>
          <thead><tr><th>Case ID</th><th>Related Address</th><th>Sealed Artifacts</th><th>Integrity</th><th>Summary</th></tr></thead>
          <tbody>${forensicRows || `<tr><td colspan="5" class="empty-note">No evidence seal recorded this run.</td></tr>`}</tbody>
        </table></div>
      </div>

      <div id="incidents" class="section-card">
        <details class="collapsible" open>
          <summary>Incident Response Dispatch</summary>
          <div class="table-scroll"><table>
            <thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Status</th><th>Created</th></tr></thead>
            <tbody>${incidentRows || `<tr><td colspan="5" class="empty-note">No incident dispatched this run.</td></tr>`}</tbody>
          </table></div>
        </details>
        <details class="collapsible" style="margin-top:16px;">
          <summary>Consensus Alerts</summary>
          <div class="table-scroll"><table>
            <thead><tr><th>Alert ID</th><th>Type</th><th>Severity</th><th>AVS Quorum</th><th>Time</th></tr></thead>
            <tbody>${consensusRows || `<tr><td colspan="5" class="empty-note">No active consensus alerts this run.</td></tr>`}</tbody>
          </table></div>
        </details>
      </div>

      <div id="compliance" class="section-card">
        <div class="section-title"><span class="title-icon">${ICON.flask}</span>OFAC Sanctions Screening</div>
        <div class="table-scroll"><table>
          <thead><tr><th>Counterparty Address</th><th>Sanction Status</th><th>Risk Tier</th><th>Detail</th></tr></thead>
          <tbody>${complianceRows || `<tr><td colspan="4" class="empty-note">No addresses screened this run.</td></tr>`}</tbody>
        </table></div>
      </div>

      <div id="trend" class="section-card">
        <div class="section-title"><span class="title-icon">${ICON.pulse}</span>Run History / Trend</div>
        ${renderTrendSparkline(data.trend)}
      </div>

      <div id="findings" class="section-card">
        <div class="section-title"><span class="title-icon">${ICON.alert}</span>Master Security Findings Register</div>
        <div class="toolbar">
          <input type="text" id="findingSearch" class="search-input" placeholder="Live search title, rule, target..." onkeyup="filterFindings()">
        </div>
        <div class="table-scroll"><table id="findingsTable">
          <thead><tr><th>ID</th><th>Severity</th><th>Zone</th><th>Finding &amp; Details</th><th>Target Context</th><th>Status</th></tr></thead>
          <tbody>${findingRows || `<tr><td colspan="6" class="empty-note">No findings recorded this run.</td></tr>`}</tbody>
        </table></div>
      </div>

    </main>
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

    const chartDefaults = {
      plugins: { legend: { labels: { color: "#cbd5e1", font: { size: 11 } } } },
      scales: {
        x: { ticks: { color: "#8b98ab", font: { size: 10 } }, grid: { color: "#1a2334" } },
        y: { ticks: { color: "#8b98ab", font: { size: 10 } }, grid: { color: "#1a2334" }, beginAtZero: true }
      }
    };

    const chartInstances = [];

    chartInstances.push(new Chart(document.getElementById("chartSeverity"), {
      type: "doughnut",
      data: {
        labels: ["Critical", "High", "Medium", "Low"],
        datasets: [{
          data: [${crit}, ${high}, ${med}, ${low}],
          backgroundColor: ["${TONE_HEX.red}", "#f97316", "${TONE_HEX.amber}", "${TONE_HEX.blue}"],
          borderWidth: 0
        }]
      },
      options: { plugins: { legend: { position: "bottom", labels: { color: "#cbd5e1", font: { size: 11 } } } } }
    }));

    chartInstances.push(new Chart(document.getElementById("chartZone"), {
      type: "bar",
      data: {
        labels: ${JSON.stringify(zoneLabels)},
        datasets: [{ label: "Findings", data: ${JSON.stringify(zoneValues)}, backgroundColor: "${TONE_HEX.blue}", borderRadius: 4 }]
      },
      options: { indexAxis: "y", plugins: { legend: { display: false } }, scales: chartDefaults.scales }
    }));

    chartInstances.push(new Chart(document.getElementById("chartGates"), {
      type: "bar",
      data: {
        labels: ["Required", "Informational"],
        datasets: [
          { label: "Passing", data: [${requiredOk}, ${infoOk}], backgroundColor: "${TONE_HEX.green}", borderRadius: 4 },
          { label: "Not Passing", data: [${requiredBad}, ${infoBad}], backgroundColor: "${TONE_HEX.red}", borderRadius: 4 }
        ]
      },
      options: { plugins: { legend: { position: "bottom", labels: { color: "#cbd5e1", font: { size: 11 } } } }, scales: { ...chartDefaults.scales, x: { ...chartDefaults.scales.x, stacked: true }, y: { ...chartDefaults.scales.y, stacked: true } } }
    }));

    ${
      trendSeq.length > 0
        ? `chartInstances.push(new Chart(document.getElementById("chartTrend"), {
      type: "line",
      data: {
        labels: ${JSON.stringify(trendLabels)},
        datasets: [
          { label: "Critical+High", data: ${JSON.stringify(trendCritHigh)}, borderColor: "${TONE_HEX.red}", backgroundColor: "rgba(239,68,68,0.15)", tension: 0.3, fill: true },
          { label: "Total Findings", data: ${JSON.stringify(trendTotal)}, borderColor: "${TONE_HEX.blue}", backgroundColor: "rgba(56,189,248,0.1)", tension: 0.3, fill: true }
        ]
      },
      options: { plugins: { legend: { position: "bottom", labels: { color: "#cbd5e1", font: { size: 11 } } } }, scales: chartDefaults.scales }
    }));`
        : `document.getElementById("chartTrend").parentElement.innerHTML = '<div class="empty-note">No run history yet — tracked from here forward only.</div>';`
    }

    // Chart.js canvases keep the pixel buffer they were drawn at on screen;
    // without an explicit resize the printed/export version can be blurry or
    // clipped against the smaller @media print box. Force a redraw at the
    // print-time container size right before printing, then restore it after.
    window.addEventListener("beforeprint", () => chartInstances.forEach((c) => c && c.resize()));
    window.addEventListener("afterprint", () => chartInstances.forEach((c) => c && c.resize()));
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
