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

// A section whose real data lives in its own reports/<x>-report.json file
// (triage-classifier, kyc-screening, gitleaks, ...) must not trust that
// file's mere existence -- a prior successful run's report can still be
// sitting on disk after a LATER run's scanner step genuinely failed and
// correctly declined to write a fresh one. The producer scripts now delete
// their own stale report on any non-success path, but checking the real
// scanner_result status here too is a second, independent safeguard against
// exactly that staleness (confirmed live, 2026-10-30: SecureVault's page
// showed VulnerableVault's leftover triage-classifier prediction because
// nothing cross-checked reports/scanners/triage-classifier.json's own
// "error" status before trusting the old report file).
function scannerOk(name: string): boolean {
  const p = resolve(process.cwd(), `reports/scanners/${name}.json`);
  if (!existsSync(p)) return false;
  try {
    return JSON.parse(readFileSync(p, "utf-8")).status === "ok";
  } catch {
    return false;
  }
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

// --- Sections A-G additions (additive only). Each reads its own real report
// file directly, same as renderDsommSection above, and shows "not run this
// cycle" rather than fabricating a value when that file is absent. ---

function renderConsensusAttackSection(): string {
  const p = resolve(process.cwd(), "reports/consensus-attack-findings.json");
  if (!existsSync(p)) {
    return `<div id="consensus-attack" class="section-card"><div class="section-title"><span class="title-icon">${ICON.node}</span>Consensus-Attack Detection</div><div class="empty-note">Not run this cycle (src/consensus/chain_attack_monitor.py did not produce a result).</div></div>`;
  }
  const findings: any[] = JSON.parse(readFileSync(p, "utf-8"));
  const rows = findings
    .map(
      (f) => `
    <tr>
      <td><b>${escapeHtml(f.metric)}</b></td>
      <td class="mono">${escapeHtml(String(f.threshold))}</td>
      <td class="mono">${escapeHtml(f.observed_value === null || f.observed_value === undefined ? "N/A" : String(f.observed_value))}</td>
      <td>${badge(f.triggered ? "TRIGGERED" : "CLEAR", f.triggered ? "red" : "green")}</td>
      <td class="dim detail-cell">${escapeHtml(f.severity || f.threat_level || f.note || "")}</td>
    </tr>`
    )
    .join("");
  const triggeredCount = findings.filter((f) => f.triggered).length;
  return `
    <div id="consensus-attack" class="section-card">
      <div class="section-title"><span class="title-icon">${ICON.node}</span>Consensus-Attack Detection (Reorg / Concentration / Eclipse / Selfish-Mining)</div>
      <div class="section-sub">${triggeredCount}/${findings.length} checks triggered this run, from a real forced Anvil reorg fed through the real, unmodified reorg/concentration/eclipse/selfish-mining detectors in <code>src/consensus/</code>. A single-signer devnet genuinely triggers concentration/eclipse by construction — see <code>chain_attack_monitor.py</code>'s own HONEST SCOPE NOTE.</div>
      <div class="table-scroll"><table>
        <thead><tr><th>Metric</th><th>Threshold</th><th>Observed</th><th>Status</th><th>Severity / Note</th></tr></thead>
        <tbody>${rows}</tbody>
      </table></div>
    </div>`;
}

function renderFlashLoanSection(): string {
  const p = resolve(process.cwd(), "reports/flashloan-findings.json");
  if (!existsSync(p)) {
    return `<div id="flashloan" class="section-card"><div class="section-title"><span class="title-icon">${ICON.flask}</span>Flash-Loan / Front-Running Detection</div><div class="empty-note">Not run this cycle.</div></div>`;
  }
  const data = JSON.parse(readFileSync(p, "utf-8"));
  let totalFlash = 0, totalFront = 0;
  const rows = (data.targets || [])
    .map((t: any) => {
      const items = [
        ...(t.flashloan_findings || []).map((f: any) => ({ ...f, kind: "flash-loan shape" })),
        ...(t.frontrunning_findings || []).map((f: any) => ({ ...f, kind: "front-running exposure" })),
      ];
      totalFlash += (t.flashloan_findings || []).length;
      totalFront += (t.frontrunning_findings || []).length;
      if (!items.length) {
        return `<tr><td class="mono dim2 detail-cell">${escapeHtml(t.target)}</td><td>${badge("CLEAN", "green")}</td><td class="dim">0 flash-loan-shape, 0 front-running findings on this target</td></tr>`;
      }
      return items
        .map(
          (f: any) =>
            `<tr><td class="mono dim2 detail-cell">${escapeHtml(t.target)}</td><td>${badge(f.kind, "red")}</td><td class="finding-cell"><b>${escapeHtml(f.function)}()</b> — ${escapeHtml(f.detail)}</td></tr>`
        )
        .join("");
    })
    .join("");
  // Dynamic, not a fixed claim: this pipeline's default vault fixture now
  // carries a real, intentional flash-loan-shaped surface (flashSwap()) on
  // VulnerableVault.sol and a real, structurally different TWAP-lite
  // mitigation (swapAtCachedRate()) on SecureVault.sol -- which real result
  // this run shows depends entirely on which target was actually scanned,
  // so the prose reflects the real counts below rather than naming either
  // contract's behaviour as fixed truth.
  const flashSub = (totalFlash + totalFront) > 0
    ? `Real solc-AST heuristic (<code>src/defi/flashloan_detector.py</code>), cross-referenced with Stage 2's Slither output. This run found ${totalFlash} real flash-loan-shape and ${totalFront} real front-running-exposure finding(s) against the actual scanned target(s) above -- not a separate fixture. A vulnerable target's flashSwap() genuinely receives value in, reads a live manipulable reserve, and pays out again in one function; a mitigated target decouples the price read into a separate, block-delayed snapshot, which this same heuristic genuinely no longer flags.`
    : `Real solc-AST heuristic (<code>src/defi/flashloan_detector.py</code>), cross-referenced with Stage 2's Slither output. 0/0 this run is a genuine clean/mitigated result for the actual scanned target(s) above, not an absence of a flash-loan surface to check: a TWAP-lite mitigation (decoupling the price read into a separate, block-delayed snapshot) structurally removes the single-function transfer-in/oracle-read/transfer-out shape this heuristic looks for.`;
  return `
    <div id="flashloan" class="section-card">
      <div class="section-title"><span class="title-icon">${ICON.flask}</span>Flash-Loan / Front-Running Detection</div>
      <div class="section-sub">${flashSub}</div>
      <div class="table-scroll"><table>
        <thead><tr><th>Target</th><th>Result</th><th>Detail</th></tr></thead>
        <tbody>${rows || `<tr><td colspan="3" class="empty-note">No targets analysed this run.</td></tr>`}</tbody>
      </table></div>
    </div>`;
}

function redactSecret(raw: string | null | undefined): string {
  // Real secret values (API tokens, webhook URLs, private keys) come
  // straight out of gitleaks' own JSON report -- this report HTML may get
  // archived, printed, or shared, so it must never render them in full.
  // Keep enough to recognize/triage WHICH secret this is without exposing
  // the usable value itself.
  const s = raw || "";
  if (s.length <= 8) return "*".repeat(s.length);
  return `${s.slice(0, 4)}${"*".repeat(Math.min(s.length - 8, 20))}${s.slice(-4)}`;
}

function renderGitleaksSection(): string {
  const p = resolve(process.cwd(), "reports/gitleaks-report.json");
  if (!existsSync(p) || !scannerOk("gitleaks")) {
    return `<div id="gitleaks" class="section-card"><div class="section-title"><span class="title-icon">${ICON.lock}</span>Gitleaks Secret/Key Leak Detection</div><div class="empty-note">Not run this cycle, or this run's own gitleaks scanner result was not ok -- see reports/scanners/gitleaks.json.</div></div>`;
  }
  const leaks: any[] = JSON.parse(readFileSync(p, "utf-8")) || [];
  const rows = leaks
    .map(
      (l: any) => `
    <tr>
      <td class="mono dim2 detail-cell">${escapeHtml(l.File)}:${escapeHtml(String(l.StartLine))}</td>
      <td>${badge(l.RuleID, "red")}</td>
      <td class="mono">${escapeHtml((l.Entropy ?? 0).toFixed ? l.Entropy.toFixed(2) : String(l.Entropy))}</td>
      <td class="mono dim detail-cell">${escapeHtml(redactSecret(l.Secret))}</td>
    </tr>`
    )
    .join("");
  return `
    <div id="gitleaks" class="section-card">
      <div class="section-title"><span class="title-icon">${ICON.lock}</span>Gitleaks Secret/Key Leak Detection</div>
      <div class="section-sub">${leaks.length} real finding(s) from this run's native <code>gitleaks detect</code> scan of the working tree. Secret values are redacted here (first/last 4 characters only) -- see <code>reports/gitleaks-report.json</code> directly, under appropriate access control, for the full value if remediating.</div>
      <div class="table-scroll"><table>
        <thead><tr><th>File:Line</th><th>Rule</th><th>Entropy</th><th>Secret (redacted)</th></tr></thead>
        <tbody>${rows || `<tr><td colspan="4" class="empty-note">No secrets detected this run.</td></tr>`}</tbody>
      </table></div>
    </div>`;
}

function renderKycSection(): string {
  const p = resolve(process.cwd(), "reports/kyc-screening-report.json");
  if (!existsSync(p) || !scannerOk("kyc-screening")) {
    return `<div id="kyc-screening" class="section-card"><div class="section-title"><span class="title-icon">${ICON.shield}</span>KYC/AML Name Screening (OpenSanctions)</div><div class="empty-note">Not run this cycle, or this run's own kyc-screening scanner result was not ok -- see reports/scanners/kyc-screening.json.</div></div>`;
  }
  const data = JSON.parse(readFileSync(p, "utf-8"));
  const screened: any[] = data.screened || [];
  const reviews: any[] = data.draft_reviews || [];
  // draft_reviews is built in run-kyc-screening.py in the same iteration
  // order as screened's flagged subset (one review per CONFIRMED/INCONCLUSIVE
  // match, in order) -- zip them back together by that real ordering, not a
  // shared id (the report carries none).
  let reviewIdx = 0;
  const rows = screened
    .map((row: any) => {
      const review = row.flagged ? reviews[reviewIdx++] : null;
      const reviewCell = review
        ? `${badge(review.status, review.status === "DRAFT_PENDING_REVIEW" ? "amber" : "green")}${review.requires_human_approval ? " " + badge("NEEDS HUMAN", "red") : ""}`
        : `<span class="dim">n/a</span>`;
      return `
    <tr>
      <td class="mono dim2 detail-cell">${escapeHtml(row.queried_name)}</td>
      <td>${badge(row.flagged ? "MATCH" : "CLEAN", row.flagged ? "red" : "green")}</td>
      <td>${badge(row.confidence, row.confidence === "CONFIRMED" ? "red" : row.confidence === "INCONCLUSIVE" ? "amber" : "green")}</td>
      <td>${reviewCell}</td>
      <td class="dim detail-cell">${escapeHtml(row.reason || "")}</td>
    </tr>`;
    })
    .join("");
  const snap = data.snapshot || {};
  const modeNote = data.mode === "demonstration-canary"
    ? "DEMONSTRATION canary (no real counterparty in this fixture pipeline)"
    : "operator-supplied name(s)";
  return `
    <div id="kyc-screening" class="section-card">
      <div class="section-title"><span class="title-icon">${ICON.shield}</span>KYC/AML Name Screening (OpenSanctions)</div>
      <div class="section-sub">${escapeHtml(modeNote)}. Screened against the real OpenSanctions sanctions/PEP snapshot (${escapeHtml(String(snap.entity_count ?? "?"))} entities, downloaded ${escapeHtml(snap.downloaded_at || "unknown")}). Any CONFIRMED/INCONCLUSIVE match produces a DraftKycReview requiring human approval -- this module never auto-blocks or auto-clears on its own.</div>
      <div class="table-scroll"><table>
        <thead><tr><th>Queried Name</th><th>Status</th><th>Confidence</th><th>Review</th><th>Detail</th></tr></thead>
        <tbody>${rows || `<tr><td colspan="5" class="empty-note">No names screened this run.</td></tr>`}</tbody>
      </table></div>
    </div>`;
}

function renderTriageClassifierSection(): string {
  const p = resolve(process.cwd(), "reports/triage-classifier-report.json");
  if (!existsSync(p) || !scannerOk("triage-classifier")) {
    return `<div id="triage-classifier" class="section-card"><div class="section-title"><span class="title-icon">${ICON.layers}</span>ML Triage / Prioritization Hint (Phase 4c)</div><div class="empty-note">Not run this cycle, or this run's own triage-classifier scanner result was not ok -- see reports/scanners/triage-classifier.json and scripts/run-triage-classifier.py's honest-skip conditions.</div></div>`;
  }
  const data = JSON.parse(readFileSync(p, "utf-8"));
  const probs: Record<string, number> = data.class_probabilities || {};
  const rows = Object.entries(probs)
    .sort((a, b) => (b[1] as number) - (a[1] as number))
    .map(([cat, prob]) => {
      const pct = Math.round((prob as number) * 100);
      const isTop = cat === data.predicted_category;
      return `<tr><td class="mono dim2 detail-cell">${escapeHtml(cat)}${isTop ? " " + badge("MOST LIKELY", "amber") : ""}</td><td>${miniBar(pct, isTop ? TONE_HEX.amber : TONE_HEX.gray)}</td><td class="dim">${pct}%</td></tr>`;
    })
    .join("");
  const mlflowLinks = [
    data.mlflow_training_run_url ? `<a href="${escapeHtml(data.mlflow_training_run_url)}" target="_blank" rel="noopener">Training run (metrics, confusion matrix, feature importances)</a>` : null,
    data.mlflow_inference_run_url ? `<a href="${escapeHtml(data.mlflow_inference_run_url)}" target="_blank" rel="noopener">This scoring run</a>` : null,
  ].filter(Boolean).join(" &nbsp;|&nbsp; ");
  const mlflowNote = mlflowLinks
    ? `<div class="dim" style="margin-top:8px; font-size:12px;">${ICON.pulse} MLflow (live training/inference history, not a static snapshot): ${mlflowLinks}</div>`
    : `<div class="dim" style="margin-top:8px; font-size:12px;">MLflow logging was not available when this ran -- see <code>reports/triage-classifier-report.json</code>'s own mlflow_* fields.</div>`;
  return `
    <div id="triage-classifier" class="section-card">
      <div class="section-title"><span class="title-icon">${ICON.layers}</span>ML Triage / Prioritization Hint (Phase 4c)</div>
      <div class="section-sub"><b>This is a prioritization hint layered on Slither's own findings for <code>${escapeHtml(data.target)}</code> -- it is NOT an independent vulnerability classifier.</b> A real scikit-learn model (<code>models/triage_classifier_v1.joblib</code>), trained on SmartBugs curated's real n=${data.n_training_samples} human-labeled contracts (10 real, badly imbalanced DASP categories -- one with a single training example). Real leave-one-out cross-validated accuracy=${(data.cv_accuracy ?? 0).toFixed(3)} (95% CI [${(data.cv_accuracy_95pct_ci?.[0] ?? 0).toFixed(3)}, ${(data.cv_accuracy_95pct_ci?.[1] ?? 0).toFixed(3)}]), macro-F1=${(data.cv_macro_f1 ?? 0).toFixed(3)}. Treat the category below as "most structurally similar to," not "confirmed as." Mythril ran ${escapeHtml(data.mythril_this_run || "unknown")} this cycle but is not part of this model's training or scoring.</div>
      <div class="table-scroll"><table>
        <thead><tr><th>DASP category (nearest-match)</th><th>Likelihood</th><th></th></tr></thead>
        <tbody>${rows || `<tr><td colspan="3" class="empty-note">No class probabilities in this run's report.</td></tr>`}</tbody>
      </table></div>
      ${mlflowNote}
    </div>`;
}

function renderRugpullSection(): string {
  const p = resolve(process.cwd(), "reports/rugpull-findings.json");
  if (!existsSync(p)) {
    return `<div id="rugpull" class="section-card"><div class="section-title"><span class="title-icon">${ICON.shield}</span>Rug-Pull Risk-Pattern Detection</div><div class="empty-note">Not run this cycle.</div></div>`;
  }
  const data = JSON.parse(readFileSync(p, "utf-8"));
  let fails = 0, passes = 0, notApplicable = 0;
  const rows = (data.targets || [])
    .flatMap((t: any) =>
      (t.checks || []).map((c: any) => {
        if (c.result === "fail") fails++;
        else if (c.result === "pass") passes++;
        else notApplicable++;
        return `
      <tr>
        <td class="mono dim2 detail-cell">${escapeHtml(t.target)}</td>
        <td><b>${escapeHtml(c.check)}</b></td>
        <td>${badge(c.result.toUpperCase(), c.result === "fail" ? "red" : c.result === "pass" ? "green" : "gray")}</td>
        <td class="dim detail-cell">${escapeHtml(c.justification)}</td>
      </tr>`;
      })
    )
    .join("");
  // Dynamic, not a fixed claim: VulnerableVault.sol now genuinely carries a
  // real rug-pull-shaped surface (an owner-gated mint() with no cap/timelock/
  // renouncement, plus an owner-gated emergencySweep()), and SecureVault.sol
  // mirrors it with a real, structurally different mitigation (a capped +
  // timelocked mint path, no sweep function at all) -- which result this run
  // shows depends entirely on which target was actually scanned.
  const rugSub = fails > 0
    ? `Real solc-AST checks (<code>src/defi/rugpull_detector.py</code>). This run found ${fails} genuinely FAILING check(s) against the actual scanned target(s) above: an owner-gated mint with no renounce/timelock path is a real centralized-power risk even though the mint call itself is access-controlled, and an owner-gated full-balance sweep is itself the classic rug-pull vector this check flags regardless of access control.`
    : passes > 0
    ? `Real solc-AST checks (<code>src/defi/rugpull_detector.py</code>). This run shows ${passes} genuine PASS(es) against the actual scanned target(s) above -- not NOT_APPLICABLE: the mint/ownership surface genuinely exists here, and is genuinely mitigated (capped + timelocked, no sweep function), which this same heuristic correctly recognizes as safe.`
    : `Real solc-AST checks (<code>src/defi/rugpull_detector.py</code>). NOT_APPLICABLE is shown as such, not folded into PASS — it means the contract has no mint/ownership/liquidity/withdraw-all surface at all, itself a real, honest finding when a target genuinely has none.`;
  return `
    <div id="rugpull" class="section-card">
      <div class="section-title"><span class="title-icon">${ICON.shield}</span>Rug-Pull Risk-Pattern Detection</div>
      <div class="section-sub">${rugSub}</div>
      <div class="table-scroll"><table>
        <thead><tr><th>Target</th><th>Check</th><th>Result</th><th>Justification</th></tr></thead>
        <tbody>${rows || `<tr><td colspan="4" class="empty-note">No targets analysed this run.</td></tr>`}</tbody>
      </table></div>
    </div>`;
}

function renderHsmSection(): string {
  const p = resolve(process.cwd(), "reports/scanners/hsm-signer.json");
  if (!existsSync(p)) {
    return `<div id="hsm" class="section-card"><div class="section-title"><span class="title-icon">${ICON.lock}</span>SoftHSM2 PKCS#11 Signing</div><div class="empty-note">Not run this cycle.</div></div>`;
  }
  const r = JSON.parse(readFileSync(p, "utf-8"));
  return `
    <div id="hsm" class="section-card">
      <div class="section-title"><span class="title-icon">${ICON.lock}</span>SoftHSM2 PKCS#11 Signing</div>
      <div class="section-sub">Software-emulated PKCS#11 HSM via SoftHSM2 — no physical HSM hardware in this lab environment, but genuinely implements the PKCS#11 standard interface. Additional to, not instead of, the HashiCorp Vault Transit path above.</div>
      <div class="infra-row">
        <div class="infra-name"><span class="infra-dot" style="color:${r.status === "ok" ? TONE_HEX.green : TONE_HEX.red};"></span>${escapeHtml(r.token_label || "SoftHSM2 token")} (${escapeHtml(r.key_type || "")})</div>
        ${badge((r.status || "unknown").toUpperCase(), toneForGateStatus(r.status))}
      </div>
      <div class="infra-detail" style="text-align:left; max-width:100%;">${escapeHtml(r.detail || "")}</div>
    </div>`;
}

function renderQuorumSigningSection(): string {
  const p = resolve(process.cwd(), "reports/scanners/quorum-signer.json");
  if (!existsSync(p)) {
    return `<div id="quorum-signing" class="section-card"><div class="section-title"><span class="title-icon">${ICON.lock}</span>k-of-n Quorum-Approval Threshold Signing</div><div class="empty-note">Not run this cycle.</div></div>`;
  }
  const r = JSON.parse(readFileSync(p, "utf-8"));
  return `
    <div id="quorum-signing" class="section-card">
      <div class="section-title"><span class="title-icon">${ICON.lock}</span>k-of-n Quorum-Approval Threshold Signing</div>
      <div class="section-sub">Third signing/approval layer over the same attestation Vault Transit and SoftHSM2 above just signed: a real ${r.counts?.quorum_threshold ?? "?"}-of-${r.counts?.quorum_total_shares ?? "?"} Shamir quorum reconstructs a secret that becomes the master key for a real 2-party MPC joint ECDSA signature (<code>src/wallet/shamir_engine.py</code> + <code>mpc_relayer_cluster.py</code> + <code>mpc_joint_signer.py</code>).</div>
      <div class="infra-row">
        <div class="infra-name"><span class="infra-dot" style="color:${r.status === "ok" ? TONE_HEX.green : TONE_HEX.red};"></span>Cluster ${escapeHtml(r.cluster_address || "")}</div>
        ${badge((r.status || "unknown").toUpperCase(), toneForGateStatus(r.status))}
      </div>
      <div class="infra-detail" style="text-align:left; max-width:100%;">${escapeHtml(r.detail || "")}</div>
    </div>`;
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

function renderVyperSection(): string {
  const p = resolve(process.cwd(), "reports/vyper-check-report.json");
  if (!existsSync(p)) {
    return `<div id="vyper" class="section-card"><div class="section-title"><span class="title-icon">${ICON.cube}</span>Vyper Compile + Static Check</div><div class="empty-note">Not run this cycle.</div></div>`;
  }
  const r = JSON.parse(readFileSync(p, "utf-8"));
  const findingRows = (r.reentrancy_shaped_findings || [])
    .map(
      (f: any) => `
    <tr><td class="mono">${escapeHtml(f.function)}()</td><td class="mono dim2">${escapeHtml((f.decorators || []).join(", ") || "none")}</td><td class="dim detail-cell">${escapeHtml(f.detail)}</td></tr>`
    )
    .join("");
  return `
    <div id="vyper" class="section-card">
      <div class="section-title"><span class="title-icon">${ICON.cube}</span>Vyper Compile + Static Check</div>
      <div class="section-sub">Real <code>vyper</code> compile (pipx-installed) of <code>${escapeHtml(r.target)}</code> — ${r.bytecode_len_bytes} bytes bytecode. One basic, honestly-scoped AST heuristic: an external call (raw_call/send/create_*) with no real <code>@nonreentrant</code> decorator — the Vyper-native equivalent of Slither's reentrancy-eth check, not a claim of deep Vyper-specific SAST.</div>
      <div class="table-scroll"><table>
        <thead><tr><th>Function</th><th>Decorators</th><th>Finding</th></tr></thead>
        <tbody>${findingRows || `<tr><td colspan="3" class="empty-note">No reentrancy-shaped findings.</td></tr>`}</tbody>
      </table></div>
    </div>`;
}

function renderEchidnaSection(): string {
  const p = resolve(process.cwd(), "reports/echidna-report.json");
  if (!existsSync(p)) {
    return `<div id="echidna" class="section-card"><div class="section-title"><span class="title-icon">${ICON.flask}</span>Echidna Property-Based Fuzzing</div><div class="empty-note">Not run this cycle.</div></div>`;
  }
  const r = JSON.parse(readFileSync(p, "utf-8"));
  const rows = (r.properties || [])
    .map(
      (prop: any) => `
    <tr>
      <td class="mono">${escapeHtml(prop.name)}</td>
      <td>${badge(prop.passed ? "PASSING" : "FALSIFIED", prop.passed ? "green" : "red")}</td>
      <td class="mono dim2 detail-cell" style="white-space:pre-wrap;">${escapeHtml(prop.detail)}</td>
    </tr>`
    )
    .join("");
  return `
    <div id="echidna" class="section-card">
      <div class="section-title"><span class="title-icon">${ICON.flask}</span>Echidna Property-Based Fuzzing</div>
      <div class="section-sub">Real <code>echidna</code> docker run against <code>test/echidna/VaultEchidnaHarness.sol</code>. A falsified property on the intentionally vulnerable default fixture is an expected, real result — the counterexample below is the fuzzer's own real, shrunk call sequence, not invented.</div>
      <div class="table-scroll"><table>
        <thead><tr><th>Property</th><th>Result</th><th>Detail</th></tr></thead>
        <tbody>${rows || `<tr><td colspan="3" class="empty-note">No properties recorded this run.</td></tr>`}</tbody>
      </table></div>
    </div>`;
}

function renderEtherscanSection(): string {
  const p = resolve(process.cwd(), "reports/etherscan-lookup-report.json");
  if (!existsSync(p) || !scannerOk("etherscan-lookup")) {
    return `<div id="etherscan" class="section-card"><div class="section-title"><span class="title-icon">${ICON.server}</span>Etherscan V2 API Lookup</div><div class="empty-note">Not run this cycle, or this run's own etherscan-lookup scanner result was not ok -- see reports/scanners/etherscan-lookup.json (most commonly: ETHERSCAN_API_KEY not seeded in Vault).</div></div>`;
  }
  const r = JSON.parse(readFileSync(p, "utf-8"));
  const modeNote = r.mode === "demonstration-canary"
    ? "DEMONSTRATION canary: a real, well-known, long-verified public contract -- NOT one of this project's own fixtures (see scripts/run-etherscan-lookup.py's own HONEST SCOPE note)."
    : "operator-supplied address.";
  const txRows = (r.recent_transactions || []).slice(0, 5)
    .map((tx: any) => `<tr><td class="mono dim2 detail-cell">${escapeHtml(tx.hash)}</td><td class="mono">${escapeHtml(tx.blockNumber)}</td><td class="mono dim2">${escapeHtml(tx.value)}</td></tr>`)
    .join("");
  return `
    <div id="etherscan" class="section-card">
      <div class="section-title"><span class="title-icon">${ICON.server}</span>Etherscan V2 API Lookup</div>
      <div class="section-sub">${escapeHtml(modeNote)} Address <code>${escapeHtml(r.address)}</code> on chain ${escapeHtml(String(r.chain_id))}.</div>
      <div class="infra-row"><div class="infra-name">Verified source</div>${badge(r.verified ? "VERIFIED" : "UNVERIFIED", r.verified ? "green" : "amber")}</div>
      <div class="infra-detail" style="text-align:left; max-width:100%;">${escapeHtml(r.contract_name || "")}${r.compiler_version ? " (" + escapeHtml(r.compiler_version) + ")" : ""}</div>
      <div class="infra-row" style="margin-top:8px;"><div class="infra-name">Balance</div><span class="mono dim2">${escapeHtml(String(r.balance_wei ?? "unknown"))} wei</span></div>
      <div class="section-sub" style="margin-top:10px;">Recent transactions (${r.tx_count_fetched ?? 0} fetched):</div>
      <div class="table-scroll"><table>
        <thead><tr><th>Tx Hash</th><th>Block</th><th>Value (wei)</th></tr></thead>
        <tbody>${txRows || `<tr><td colspan="3" class="empty-note">No transactions fetched.</td></tr>`}</tbody>
      </table></div>
    </div>`;
}

function renderIndexerSection(): string {
  const p = resolve(process.cwd(), "reports/indexer-report.json");
  if (!existsSync(p) || !scannerOk("indexer")) {
    return `<div id="indexer" class="section-card"><div class="section-title"><span class="title-icon">${ICON.cube}</span>Real On-Chain Indexer</div><div class="empty-note">Not run this cycle, or this run's own indexer scanner result was not ok -- see reports/scanners/indexer.json.</div></div>`;
  }
  const r = JSON.parse(readFileSync(p, "utf-8"));
  const rows = (r.sample_documents || [])
    .map((d: any) => `
    <tr>
      <td class="mono dim2">${escapeHtml(d.target_contract)}</td>
      <td>${badge(d.doc_type === "decoded_event" ? (d.event_name || "EVENT") : "TX ACTIVITY", d.doc_type === "decoded_event" ? "green" : "gray")}</td>
      <td class="mono">${escapeHtml(String(d.block_number))}</td>
      <td class="mono dim2 detail-cell">${escapeHtml(d.tx_hash)}</td>
    </tr>`)
    .join("");
  return `
    <div id="indexer" class="section-card">
      <div class="section-title"><span class="title-icon">${ICON.cube}</span>Real On-Chain Indexer</div>
      <div class="section-sub">A short-lived, per-run indexing pass against its own dedicated ephemeral Anvil instance -- NOT a persistent standing daemon, and NOT a subscription to avs_consensus.py's own (already torn-down) nodes. See <code>src/onchain/indexer.py</code>'s own HONEST SCOPE note. ${r.decoded_events ?? 0} real decoded event(s) (DeFiLendingVault/StakingRewardsVault) + ${r.transaction_activity_docs ?? 0} real transaction-activity doc(s) (VulnerableVault/SecureVault emit no events) indexed into Elasticsearch index <code>${escapeHtml(r.es_index || "")}</code>.</div>
      <div class="table-scroll"><table>
        <thead><tr><th>Contract</th><th>Type</th><th>Block</th><th>Tx Hash</th></tr></thead>
        <tbody>${rows || `<tr><td colspan="4" class="empty-note">No documents indexed this run.</td></tr>`}</tbody>
      </table></div>
    </div>`;
}

function renderZkAttestationSection(): string {
  const p = resolve(process.cwd(), "reports/zk-attestation-report.json");
  if (!existsSync(p) || !scannerOk("zk-attestation")) {
    return `<div id="zk-attestation" class="section-card"><div class="section-title"><span class="title-icon">${ICON.lock}</span>Simplified-ZK Compliance Attestation</div><div class="empty-note">Not run this cycle, or this run's own zk-attestation scanner result was not ok -- see reports/scanners/zk-attestation.json (most commonly: this run's OFAC screening report is missing).</div></div>`;
  }
  const r = JSON.parse(readFileSync(p, "utf-8"));
  const rows = (r.attestations || [])
    .map((a: any) => {
      const generated = a.outcome === "proof_generated";
      return `
    <tr>
      <td class="mono dim2 detail-cell">${escapeHtml(a.address)}</td>
      <td>${badge(generated ? "PROOF GENERATED" : "CORRECTLY REFUSED", generated ? "green" : "amber")}</td>
      <td class="mono dim2 detail-cell">${generated ? escapeHtml(a.proof?.proof_id || "") : escapeHtml(a.refusal_reason || "")}</td>
      <td>${generated ? badge(a.verified_with_witness && a.verified_public_only ? "VERIFIED" : "VERIFY FAILED", a.verified_with_witness && a.verified_public_only ? "green" : "red") : `<span class="dim">n/a</span>`}</td>
    </tr>`;
    })
    .join("");
  return `
    <div id="zk-attestation" class="section-card">
      <div class="section-title"><span class="title-icon">${ICON.lock}</span>Simplified-ZK Compliance Attestation</div>
      <div class="section-sub"><strong>${escapeHtml(r.scheme_honest_label || "")}</strong>. Real commitment/challenge-response proofs over this run's own OFAC-screened addresses (${r.sanctioned_universe_size ?? "?"}-address real OFAC SDN universe, snapshot ${escapeHtml(r.ofac_snapshot_meta?.downloaded_at || "unknown")}). Volume/threshold are a documented demonstration canary (${escapeHtml(r.mode || "")}) -- this fixture pipeline has no real transaction volume data. The private witness (blinding factors) is never written to this or any report file.</div>
      <div class="table-scroll"><table>
        <thead><tr><th>Address</th><th>Outcome</th><th>Proof ID / Refusal Reason</th><th>Re-Verification</th></tr></thead>
        <tbody>${rows || `<tr><td colspan="4" class="empty-note">No attestations attempted this run.</td></tr>`}</tbody>
      </table></div>
    </div>`;
}

function renderZkOfacSection(): string {
  const p = resolve(process.cwd(), "test/zk-ofac/zk-ofac-summary.json");
  if (!existsSync(p)) {
    return `<div id="zk-ofac" class="section-card"><div class="section-title"><span class="title-icon">${ICON.lock}</span>ZK-OFAC Compliance Circuit</div><div class="empty-note">Not available.</div></div>`;
  }
  const r = JSON.parse(readFileSync(p, "utf-8"));
  return `
    <div id="zk-ofac" class="section-card">
      <div class="section-title"><span class="title-icon">${ICON.lock}</span>ZK-OFAC Compliance Circuit</div>
      <div class="section-sub">${escapeHtml(r.note)} ${badge("STANDALONE — NOT PIPELINE-WIRED", "amber")}</div>
      <div class="infra-row"><div class="infra-name">Circuit (${escapeHtml(r.circuit.protocol)}/${escapeHtml(r.circuit.curve)})</div><span class="mono dim2">${r.circuit.total_constraints} constraints, ${r.circuit.public_inputs} public / ${r.circuit.private_inputs} private input</span></div>
      <div class="infra-row"><div class="infra-name">Clean-address proof</div>${badge(r.clean_address_proof.verification_result, "green")}</div>
      <div class="infra-detail" style="text-align:left; max-width:100%;">Address never appears in the proof or public signals (private input).</div>
      <div class="infra-row"><div class="infra-name">Flagged-address proof attempt</div>${badge(r.flagged_address_proof.witness_generation_result, "red")}</div>
      <div class="infra-detail" style="text-align:left; max-width:100%;">${escapeHtml(r.flagged_address_proof.failure_reason)}</div>
      <div class="dim" style="font-size:11.5px; margin-top:10px;">Reproducible from <code class="mono">${escapeHtml(r.circuit.file)}</code> and the setup commands in its own comments.</div>
    </div>`;
}

function loadControlGuidance(): any[] {
  try {
    return JSON.parse(readFileSync(resolve(process.cwd(), "config/control-guidance.json"), "utf-8"));
  } catch {
    return [];
  }
}
const CONTROL_GUIDANCE = loadControlGuidance();

function guidanceFor(id: string, frameworkFallbackName: string): string {
  const entry = CONTROL_GUIDANCE.find((g: any) => g.id === id);
  if (!entry) {
    return `<span class="dim2">see ${escapeHtml(frameworkFallbackName)}'s official reference</span>`;
  }
  return `<span class="dim2"><b>${escapeHtml(entry.shortTitle)}:</b> ${escapeHtml(entry.guidance)}</span> <a href="${escapeHtml(entry.sourceUrl)}" target="_blank" rel="noopener">[ref]</a>`;
}

function renderGovernanceEnrichmentSection(): string {
  const p = resolve(process.cwd(), "reports/enriched-findings-report.json");
  if (!existsSync(p)) {
    return `<div id="governance-enrichment" class="section-card"><div class="section-title"><span class="title-icon">${ICON.shield}</span>Governance Framework Mapping (MITRE ATT&CK / CIS v8 / ISO 27001)</div><div class="empty-note">Not run this cycle -- see reports/scanners/governance-enrichment.json.</div></div>`;
  }
  const r = JSON.parse(readFileSync(p, "utf-8"));
  if (r.status !== "ok") {
    return `
    <div id="governance-enrichment" class="section-card">
      <div class="section-title"><span class="title-icon">${ICON.shield}</span>Governance Framework Mapping (MITRE ATT&CK / CIS v8 / ISO 27001)</div>
      <div class="infra-row"><div class="infra-name">Enrichment status</div>${badge("NOT RUN", "amber")}</div>
      <div class="empty-note">Enrichment unavailable this run: ${escapeHtml(r.reason || "unknown reason")}.</div>
    </div>`;
  }
  const rows = (r.enriched || []).slice(0, 25)
    .map((f: any) => `
    <tr>
      <td class="mono dim2 detail-cell">${escapeHtml(f.title)}</td>
      <td>${badge(f.severity, f.severity === "HIGH" || f.severity === "CRITICAL" ? "red" : f.severity === "MEDIUM" ? "amber" : "gray")}</td>
      <td class="mono">${escapeHtml(f.governance.mitreAttack.techniqueId)} <span class="dim2">(${escapeHtml(f.governance.mitreAttack.tactic)})</span></td>
      <td class="mono">${escapeHtml(f.governance.cisControls.controlId)}</td>
      <td class="mono">${escapeHtml(f.governance.iso27001.controlId)}</td>
      <td style="font-size:11.5px; max-width:360px;">
        <div style="margin-bottom:4px;"><b class="dim2">ATT&CK:</b> ${guidanceFor(f.governance.mitreAttack.techniqueId, "MITRE ATT&CK")}</div>
        <div style="margin-bottom:4px;"><b class="dim2">CIS:</b> ${guidanceFor(f.governance.cisControls.controlId, "CIS Controls v8")}</div>
        <div><b class="dim2">ISO:</b> ${guidanceFor(f.governance.iso27001.controlId, "ISO/IEC 27001")}</div>
      </td>
    </tr>`)
    .join("");
  return `
    <div id="governance-enrichment" class="section-card">
      <div class="section-title"><span class="title-icon">${ICON.shield}</span>Governance Framework Mapping (MITRE ATT&CK / CIS v8 / ISO 27001)</div>
      <div class="section-sub">Keyword-heuristic mapping (scripts/enrich-findings.mts) from this run's own real SAST/symbolic findings to MITRE ATT&CK technique IDs, CIS Controls v8, and ISO/IEC 27001:2022 controls -- informational metadata only, never a security gate. ${r.enriched.length} finding(s) mapped. Mitigation Guidance is original project commentary (config/control-guidance.json), never official framework text.</div>
      <div class="table-scroll"><table>
        <thead><tr><th>Finding</th><th>Severity</th><th>ATT&CK Technique</th><th>CIS v8</th><th>ISO 27001</th><th>Mitigation Guidance</th></tr></thead>
        <tbody>${rows || `<tr><td colspan="6" class="empty-note">No findings enriched this run.</td></tr>`}</tbody>
      </table></div>
    </div>`;
}

function renderStrideCoverageSection(): string {
  const p = resolve(process.cwd(), "reports/scanners/stride-coverage.json");
  if (!existsSync(p)) {
    return `<div id="stride-coverage" class="section-card"><div class="section-title"><span class="title-icon">${ICON.shield}</span>STRIDE Coverage Scorecard</div><div class="empty-note">Not run this cycle.</div></div>`;
  }
  const r = JSON.parse(readFileSync(p, "utf-8"));
  const letters = ["Spoofing", "Tampering", "Repudiation", "Information Disclosure", "Denial of Service", "Elevation of Privilege"];
  const rows = letters.map((cat) => {
    const catData = r.categories?.[cat];
    const entries = (catData?.entries || []).filter((e: any) => !e.stale);
    const covered = entries.length > 0;
    const evidence = entries
      .map((e: any) => `<div class="mono dim2 detail-cell" style="margin-top:2px;">${escapeHtml(e.file)}:${e.line} — ${escapeHtml(e.description)}</div>`)
      .join("");
    return `
    <div class="infra-row" style="align-items:flex-start;">
      <div class="infra-name">${badge(cat.split(" ")[0].toUpperCase(), covered ? "green" : "amber")} ${escapeHtml(cat)}</div>
      <div style="text-align:left; max-width:70%;">${covered ? evidence : `<span class="dim2">not covered -- no real control in this repo maps to this category</span>`}</div>
    </div>`;
  }).join("");
  const unreviewed: string[] = r.unreviewed_files || [];
  const unreviewedNote = r.baseline_established
    ? `<div class="section-sub" style="margin-top:8px;">First run: this is the baseline snapshot for drift detection. Unreviewed-file tracking starts from the next run.</div>`
    : unreviewed.length > 0
      ? `<div class="infra-row" style="margin-top:8px;"><div class="infra-name">${badge(`UNREVIEWED FILES: ${unreviewed.length}`, "amber")}</div><span class="dim2">new/changed since last snapshot, not yet referenced anywhere in the STRIDE map</span></div>`
      : `<div class="section-sub" style="margin-top:8px;">No new or changed files outside the existing STRIDE map since the last run.</div>`;
  return `
    <div id="stride-coverage" class="section-card">
      <div class="section-title"><span class="title-icon">${ICON.shield}</span>STRIDE Coverage Scorecard: ${r.categories_covered ?? 0}/6</div>
      <div class="section-sub">${r.status !== "ok" ? `Self-verification status: ${escapeHtml(r.status)} (${(r.stale_entries || []).length} stale entry/entries).` : "All evidence file:line references re-verified against the live repo this run."} Source of truth: <code>config/stride-coverage-map.json</code>, kept in sync with <code>docs/STRIDE-CROSSWALK.md</code>.</div>
      ${rows}
      ${unreviewedNote}
    </div>`;
}

function renderDreadScoringSection(): string {
  const p = resolve(process.cwd(), "reports/dread-scoring-report.json");
  if (!existsSync(p)) {
    return `<div id="dread-scoring" class="section-card"><div class="section-title"><span class="title-icon">${ICON.alert}</span>DREAD Risk Scoring (5-Factor Vector)</div><div class="empty-note">Not run this cycle -- see reports/scanners/dread-scoring.json.</div></div>`;
  }
  const r = JSON.parse(readFileSync(p, "utf-8"));
  if (r.status !== "ok") {
    return `
    <div id="dread-scoring" class="section-card">
      <div class="section-title"><span class="title-icon">${ICON.alert}</span>DREAD Risk Scoring (5-Factor Vector)</div>
      <div class="infra-row"><div class="infra-name">Scoring status</div>${badge("NOT RUN", "amber")}</div>
      <div class="empty-note">DREAD scoring unavailable this run: ${escapeHtml(r.reason || "unknown reason")}.</div>
    </div>`;
  }
  const rows = (r.scored || []).slice(0, 25)
    .map((f: any) => `
    <tr>
      <td class="mono dim2 detail-cell">${escapeHtml(f.title)}</td>
      <td>${badge(f.severity, f.severity === "HIGH" || f.severity === "CRITICAL" ? "red" : f.severity === "MEDIUM" ? "amber" : "gray")}</td>
      <td class="mono">${f.dread.damage}</td>
      <td class="mono">${f.dread.reproducibility}</td>
      <td class="mono">${f.dread.exploitability}</td>
      <td class="mono">${f.dread.affectedUsers}</td>
      <td class="mono">${f.dread.discoverability}</td>
      <td class="mono"><b>${f.dread.score}</b></td>
    </tr>`)
    .join("");
  return `
    <div id="dread-scoring" class="section-card">
      <div class="section-title"><span class="title-icon">${ICON.alert}</span>DREAD Risk Scoring (5-Factor Vector)</div>
      <div class="section-sub">Real 5-factor DREAD vectors (Damage / Reproducibility / Exploitability / Affected Users / Discoverability, scripts/normalize-reports.mts) computed per-finding from this run's own real SAST/symbolic findings -- informational metadata only, never a security gate. ${r.scored.length} finding(s) scored. A separate, simpler per-run severity-based DREAD proxy also feeds this project's Grafana dashboard ("DREAD Risk Score" panel, via scripts/ship-siem-telemetry.py); the two are intentionally not reconciled here -- they answer different questions (per-finding 5-factor breakdown vs. a single coarse per-run number) and are computed by different, independently-tested code paths.</div>
      <div class="table-scroll"><table>
        <thead><tr><th>Finding</th><th>Severity</th><th>Dmg</th><th>Repro</th><th>Exploit</th><th>Affected</th><th>Discov</th><th>Score</th></tr></thead>
        <tbody>${rows || `<tr><td colspan="8" class="empty-note">No findings scored this run.</td></tr>`}</tbody>
      </table></div>
    </div>`;
}

function kpiGovernanceEnrichedCount(): string | number {
  const p = resolve(process.cwd(), "reports/enriched-findings-report.json");
  if (!existsSync(p)) return "N/A";
  try {
    const r = JSON.parse(readFileSync(p, "utf-8"));
    return r.status === "ok" ? (r.enriched || []).length : "N/A";
  } catch {
    return "N/A";
  }
}

function kpiStrideCoverageLabel(): string {
  const p = resolve(process.cwd(), "reports/scanners/stride-coverage.json");
  if (!existsSync(p)) return "N/A";
  try {
    const r = JSON.parse(readFileSync(p, "utf-8"));
    return typeof r.categories_covered === "number" ? `${r.categories_covered}/6` : "N/A";
  } catch {
    return "N/A";
  }
}

function kpiDreadScoredCount(): string | number {
  const p = resolve(process.cwd(), "reports/dread-scoring-report.json");
  if (!existsSync(p)) return "N/A";
  try {
    const r = JSON.parse(readFileSync(p, "utf-8"));
    return r.status === "ok" ? (r.scored || []).length : "N/A";
  } catch {
    return "N/A";
  }
}

function kpiDsommMaturity(): string {
  const p = resolve(process.cwd(), "reports/scanners/dsomm.json");
  if (!existsSync(p)) return "N/A";
  try {
    const r = JSON.parse(readFileSync(p, "utf-8"));
    if (r.status !== "ok") return "N/A";
    const assessed = r.counts?.activities_assessed;
    const total = r.counts?.activities_total;
    return (typeof assessed === "number" && typeof total === "number") ? `${assessed}/${total}` : "N/A";
  } catch {
    return "N/A";
  }
}

function kpiZapFindings(): string | number {
  const p = resolve(process.cwd(), "reports/scanners/zap.json");
  if (!existsSync(p)) return "N/A";
  try {
    const r = JSON.parse(readFileSync(p, "utf-8"));
    if (r.status !== "ok") return "N/A";
    const c = r.counts || {};
    return Number(c.high || 0) + Number(c.medium || 0) + Number(c.low || 0);
  } catch {
    return "N/A";
  }
}

function kpiLynisHardeningIndex(): string | number {
  const p = resolve(process.cwd(), "reports/scanners/lynis.json");
  if (!existsSync(p)) return "N/A";
  try {
    const r = JSON.parse(readFileSync(p, "utf-8"));
    if (r.status !== "ok") return "N/A";
    const idx = r.counts?.hardening_index;
    return typeof idx === "number" ? idx : "N/A";
  } catch {
    return "N/A";
  }
}

function kpiGitleaksCount(): string | number {
  const p = resolve(process.cwd(), "reports/gitleaks-report.json");
  if (!existsSync(p) || !scannerOk("gitleaks")) return "N/A";
  try {
    const leaks = JSON.parse(readFileSync(p, "utf-8")) || [];
    return Array.isArray(leaks) ? leaks.length : "N/A";
  } catch {
    return "N/A";
  }
}

function renderCriticalFindingsGlance(v104: any): string {
  function row(id: string, label: string, status: string, tone: Tone, detail: string): string {
    return `
    <tr>
      <td><a href="#${id}" style="color:inherit; text-decoration:none;"><b>${escapeHtml(label)}</b></a></td>
      <td>${badge(status, tone)}</td>
      <td class="dim detail-cell">${escapeHtml(detail)}</td>
    </tr>`;
  }

  const rows: string[] = [];

  const avs = v104.avs_consensus;
  const avsIsHalt = avs?.decision?.includes("EXPLOIT") || avs?.decision?.includes("HALT");
  rows.push(
    avs
      ? row("subsystems", "AVS Consensus (3-node exploit replay)", avs.decision, avsIsHalt ? "red" : "green", `${avs.agreement_ratio} node agreement -- real EVM execution trace, not simulated.`)
      : row("subsystems", "AVS Consensus (3-node exploit replay)", "NOT RUN", "gray", "")
  );

  const swarm = v104.langgraph_swarm;
  const swarmVotes = swarm?.votes || {};
  rows.push(
    swarm
      ? row("subsystems", "LangGraph 7-Agent Swarm Vote", swarm.decision, swarm.decision === "HALT_CONFIRMED" ? "red" : "green", `${swarmVotes.halt || 0}/${swarm.agents_count || 7} agents voted HALT.`)
      : row("subsystems", "LangGraph 7-Agent Swarm Vote", "NOT RUN", "gray", "")
  );

  const caPath = resolve(process.cwd(), "reports/consensus-attack-findings.json");
  try {
    if (existsSync(caPath)) {
      const ca: any[] = JSON.parse(readFileSync(caPath, "utf-8"));
      const triggeredList = ca.filter((f) => f.triggered);
      rows.push(row("consensus-attack", "Consensus-Attack Monitor", `${triggeredList.length}/${ca.length} TRIGGERED`, triggeredList.length > 0 ? "red" : "green", triggeredList.map((f) => f.metric).join(", ")));
    } else {
      rows.push(row("consensus-attack", "Consensus-Attack Monitor", "NOT RUN", "gray", ""));
    }
  } catch {
    rows.push(row("consensus-attack", "Consensus-Attack Monitor", "NOT RUN", "gray", ""));
  }

  const echPath = resolve(process.cwd(), "reports/echidna-report.json");
  try {
    if (existsSync(echPath)) {
      const ech = JSON.parse(readFileSync(echPath, "utf-8"));
      const reentered = (ech.properties || []).find((p: any) => p.name === "echidna_withdraw_never_reentered");
      rows.push(
        reentered
          ? row("echidna", "Echidna Reentrancy Counterexample", reentered.passed ? "NOT FALSIFIED" : "FALSIFIED", reentered.passed ? "green" : "red", reentered.passed ? "No real counterexample found this run." : "A real counterexample was found -- see the Echidna Fuzzing section for the call sequence.")
          : row("echidna", "Echidna Reentrancy Counterexample", "NOT RUN", "gray", "")
      );
    } else {
      rows.push(row("echidna", "Echidna Reentrancy Counterexample", "NOT RUN", "gray", ""));
    }
  } catch {
    rows.push(row("echidna", "Echidna Reentrancy Counterexample", "NOT RUN", "gray", ""));
  }

  const ofacPath = resolve(process.cwd(), "reports/ofac-screening-report.json");
  try {
    if (existsSync(ofacPath) && scannerOk("ofac-screening")) {
      const ofac = JSON.parse(readFileSync(ofacPath, "utf-8"));
      const screened: any[] = ofac.screened || [];
      const flagged = screened.filter((s) => s.flagged);
      rows.push(row("compliance", "OFAC Sanctions Screening", `${flagged.length}/${screened.length} FLAGGED`, flagged.length > 0 ? "red" : "green", flagged.map((f) => `${f.entity || f.address} (${f.risk_tier})`).join(", ")));
    } else {
      rows.push(row("compliance", "OFAC Sanctions Screening", "NOT RUN", "gray", ""));
    }
  } catch {
    rows.push(row("compliance", "OFAC Sanctions Screening", "NOT RUN", "gray", ""));
  }

  const kycPath = resolve(process.cwd(), "reports/kyc-screening-report.json");
  try {
    if (existsSync(kycPath) && scannerOk("kyc-screening")) {
      const kyc = JSON.parse(readFileSync(kycPath, "utf-8"));
      const screened: any[] = kyc.screened || [];
      const flagged = screened.filter((s) => s.flagged);
      rows.push(row("kyc-screening", "KYC/AML Name Screening", `${flagged.length}/${screened.length} FLAGGED`, flagged.length > 0 ? "amber" : "green", flagged.map((f) => f.queried_name).join(", ")));
    } else {
      rows.push(row("kyc-screening", "KYC/AML Name Screening", "NOT RUN", "gray", ""));
    }
  } catch {
    rows.push(row("kyc-screening", "KYC/AML Name Screening", "NOT RUN", "gray", ""));
  }

  return `
    <div id="critical-glance" class="section-card">
      <div class="section-title"><span class="title-icon">${ICON.alert}</span>Critical Findings At-a-Glance</div>
      <div class="section-sub">Six real results already computed elsewhere in this report, shown together here for a fast skim. Click any row to jump to its full detail section below.</div>
      <div class="table-scroll"><table>
        <thead><tr><th>Finding</th><th>Status</th><th>Detail</th></tr></thead>
        <tbody>${rows.join("")}</tbody>
      </table></div>
    </div>`;
}

function renderLynisSection(): string {
  const p = resolve(process.cwd(), "reports/lynis-governance-report.json");
  if (!existsSync(p) || !scannerOk("lynis")) {
    return `<div id="lynis" class="section-card"><div class="section-title"><span class="title-icon">${ICON.server}</span>Lynis Host-Compliance Audit</div><div class="empty-note">Not run this cycle, or this run's own lynis scanner result was not ok -- see reports/scanners/lynis.json.</div></div>`;
  }
  const r = JSON.parse(readFileSync(p, "utf-8"));
  let policyMappings: any[] = [];
  try {
    policyMappings = JSON.parse(readFileSync(resolve(process.cwd(), "config/governance-policy.json"), "utf-8")).mappings || [];
  } catch {
    // reference URLs become unavailable, not fatal
  }
  const refFor = (testId: string) => policyMappings.find((m: any) => m.testId === testId)?.providerReference;

  const findingRows = (r.findings || [])
    .map((f: any) => `
    <tr>
      <td>${badge(f.kind.toUpperCase(), f.kind === "warning" ? "red" : "amber")}</td>
      <td class="mono dim2 detail-cell">${escapeHtml(f.testId)}</td>
      <td class="mono">${f.occurrences}</td>
      <td class="dim detail-cell">${f.relatedNistControls.length ? escapeHtml(f.relatedNistControls.join(", ")) : `<span class="dim2">unmapped</span>`}</td>
    </tr>`)
    .join("");

  const controlRows = (r.controlEvidence || [])
    .map((c: any) => `
    <tr>
      <td class="mono">${escapeHtml(c.controlId)}</td>
      <td>${escapeHtml(c.title)}</td>
      <td>${badge(c.status.toUpperCase(), c.status === "needs-review" ? "amber" : "gray")}</td>
      <td class="dim detail-cell">${escapeHtml(c.relationship)}${refFor(c.relatedTestId) ? ` <a href="${escapeHtml(refFor(c.relatedTestId))}" target="_blank" rel="noopener">[remediation ref]</a>` : ""}</td>
      <td style="font-size:11.5px; max-width:360px;">${guidanceFor(c.controlId, "NIST SP 800-53")}</td>
    </tr>`)
    .join("");

  return `
    <div id="lynis" class="section-card">
      <div class="section-title"><span class="title-icon">${ICON.server}</span>Lynis Host-Compliance Audit</div>
      <div class="section-sub">${badge("REVIEW-REQUIRED -- NOT A COMPLIANCE/CERTIFICATION CLAIM", "amber")} Non-root, no-plugins audit of this host (provider ${escapeHtml(r.provider?.name)} ${escapeHtml(r.provider?.programVersion)}). Partial, project-authored NIST SP 800-53 Rev. 5 crosswalk for 2 controls only -- not an official crosswalk, not a full catalog assessment, no automatic remediation, no certification claim (see config/governance-policy.json's own scope block).</div>
      <div class="infra-row"><div class="infra-name">Hardening Index</div><span class="mono dim2">${r.providerMetric?.hardeningIndex ?? "?"} / 100</span></div>
      <div class="infra-row"><div class="infra-name">Tests Run</div><span class="mono dim2">${r.summary?.providerTestsDone ?? "?"}</span></div>
      <div class="infra-row"><div class="infra-name">Warning / Suggestion Records</div><span class="mono dim2">${r.summary?.warningRecords ?? 0} / ${r.summary?.suggestionRecords ?? 0}</span></div>
      <div class="section-sub" style="margin-top:10px;">Individual findings (real Lynis test IDs; host field values and raw finding text are intentionally never retained):</div>
      <div class="table-scroll"><table>
        <thead><tr><th>Kind</th><th>Test ID</th><th>Occurrences</th><th>Related NIST Control</th></tr></thead>
        <tbody>${findingRows || `<tr><td colspan="4" class="empty-note">No findings this run.</td></tr>`}</tbody>
      </table></div>
      <div class="section-sub" style="margin-top:10px;">Control evidence (partial, needs-review only -- never a pass/fail compliance verdict). Mitigation Guidance is original project commentary (config/control-guidance.json), never official NIST text:</div>
      <div class="table-scroll"><table>
        <thead><tr><th>Control</th><th>Title</th><th>Status</th><th>Relationship / Remediation</th><th>Mitigation Guidance</th></tr></thead>
        <tbody>${controlRows || `<tr><td colspan="5" class="empty-note">No control evidence this run.</td></tr>`}</tbody>
      </table></div>
    </div>`;
}

function renderOsintSection(): string {
  const p = resolve(process.cwd(), "reports/scanners/osint.json");
  if (!existsSync(p)) {
    return `<div id="osint" class="section-card"><div class="section-title"><span class="title-icon">${ICON.server}</span>OSINT Threat Intel (AbuseIPDB + OFAC)</div><div class="empty-note">Not run this cycle.</div></div>`;
  }
  const r = JSON.parse(readFileSync(p, "utf-8"));
  const ip = r.ip_reputation || {};
  const addr = r.smart_contract_threat || {};
  return `
    <div id="osint" class="section-card">
      <div class="section-title"><span class="title-icon">${ICON.server}</span>OSINT Threat Intel (AbuseIPDB + OFAC)</div>
      <div class="section-sub">${badge("DEMONSTRATION CANARY -- NOT LIVE PRODUCTION TRAFFIC", "amber")} src/observability/threat_intel.py's LiveThreatIntelEngine, exercised against fixed demonstration targets, not real inbound traffic.</div>
      <div class="infra-row"><div class="infra-name">AbuseIPDB: 118.25.6.39 (AbuseIPDB's own documented example IP)</div>${badge(ip.status ? ip.status.toUpperCase() : "NOT RUN", ip.status === "ok" ? (ip.flagged ? "red" : "green") : "amber")}</div>
      <div class="infra-detail" style="text-align:left; max-width:100%;">${ip.status === "ok" ? `abuse_score=${ip.abuse_score}, country=${escapeHtml(ip.country || "?")}` : escapeHtml(ip.detail || "")}</div>
      <div class="infra-row" style="margin-top:8px;"><div class="infra-name">OFAC SDN: Lazarus Group demo address</div>${badge(addr.flagged ? "FLAGGED" : "CLEAN", addr.flagged ? "red" : "green")}</div>
      <div class="infra-detail" style="text-align:left; max-width:100%;">${escapeHtml(addr.attribution || addr.detail || "")} -- duplicates the real run-ofac-screening.py step; not an independent signal.</div>
    </div>`;
}

function kpiOsintStatus(): string {
  const p = resolve(process.cwd(), "reports/scanners/osint.json");
  if (!existsSync(p)) return "N/A";
  try {
    const r = JSON.parse(readFileSync(p, "utf-8"));
    return (r.status || "N/A").toUpperCase();
  } catch {
    return "N/A";
  }
}

function renderNvdMirrorSection(): string {
  const p = resolve(process.cwd(), "reports/raw/sca-summary.json");
  if (!existsSync(p)) {
    return `<div id="nvd-mirror" class="section-card"><div class="section-title"><span class="title-icon">${ICON.server}</span>NVD Offline-Mirror Status</div><div class="empty-note">Not run this cycle (SCA lookup did not produce a raw summary).</div></div>`;
  }
  const s = JSON.parse(readFileSync(p, "utf-8"));
  const used = s.offlineMirrorUsed === true;
  const missing = s.nvdMissingIds || [];
  return `
    <div id="nvd-mirror" class="section-card">
      <div class="section-title"><span class="title-icon">${ICON.server}</span>NVD Offline-Mirror Status (this run)</div>
      <div class="section-sub">Whether <code>scripts/run-sca.cjs</code>'s SCA lookup this run actually consulted the local <code>~/.local/state/nvd-mirror</code> SQLite index before any live NVD call.</div>
      <div class="infra-row"><div class="infra-name"><span class="infra-dot" style="color:${used ? TONE_HEX.green : TONE_HEX.amber};"></span>Offline mirror used this run</div>${badge(used ? "YES" : "NO (live NVD API)", used ? "green" : "amber")}</div>
      <div class="infra-row"><div class="infra-name">NVD CVEs requested / returned from mirror</div><span class="mono">${s.nvdRequestedCves ?? "N/A"} / ${s.nvdReturnedCves ?? "N/A"}</span></div>
      <div class="infra-row"><div class="infra-name">Missing from mirror (fell back live)</div><span class="mono">${missing.length ? escapeHtml(JSON.stringify(missing)) : "none"}</span></div>
      <div class="infra-detail" style="text-align:left; max-width:100%;">OSV package→advisory matching (<code>networkLookupExecuted=${escapeHtml(String(s.networkLookupExecuted))}</code>) always goes live by design — version-range matching needs the live API regardless of the mirror; this is documented, not a gap.</div>
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

  // --- MITRE ATT&CK technique frequency, for the Visual Overview chart ---
  const attackPath = resolve(process.cwd(), "reports/enriched-findings-report.json");
  let attackLabels: string[] = [];
  let attackValues: number[] = [];
  if (existsSync(attackPath)) {
    try {
      const enr = JSON.parse(readFileSync(attackPath, "utf-8"));
      if (enr.status === "ok") {
        const attackCounts: Record<string, number> = {};
        for (const f of enr.enriched || []) {
          const t = f.governance?.mitreAttack;
          const key = t ? `${t.techniqueId} (${t.techniqueName})` : "unknown";
          attackCounts[key] = (attackCounts[key] || 0) + 1;
        }
        const sorted = Object.entries(attackCounts).sort((a, b) => b[1] - a[1]);
        attackLabels = sorted.map(([k]) => k);
        attackValues = sorted.map(([, v]) => v);
      }
    } catch {
      // leave empty -- chart renders its own empty-note below
    }
  }

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
      <a href="#dsomm">OWASP DSOMM Maturity</a>
      <a href="#consensus-attack">Consensus-Attack Detection</a>
      <a href="#flashloan">Flash-Loan / Front-Running</a>
      <a href="#gitleaks">Gitleaks Secret Scan</a>
      <a href="#kyc-screening">KYC/AML Screening</a>
      <a href="#triage-classifier">ML Triage Hint</a>
      <a href="#rugpull">Rug-Pull Detection</a>
      <a href="#hsm">SoftHSM2 Signing</a>
      <a href="#quorum-signing">Quorum Threshold Signing</a>
      <a href="#sar-draft">Draft SAR</a>
      <a href="#vyper">Vyper Check</a>
      <a href="#echidna">Echidna Fuzzing</a>
      <a href="#zk-ofac">ZK-OFAC Circuit</a>
      <a href="#governance-enrichment">Governance Mapping</a>
      <a href="#stride-coverage">STRIDE Coverage</a>
      <a href="#dread-scoring">DREAD Scoring</a>
      <a href="#nvd-mirror">NVD Offline Mirror</a>
      <a href="#lynis">Lynis Audit</a>
      <a href="#wallet">Wallet Simulation</a>
      <a href="#forensics">Forensics &amp; Custody</a>
      <a href="#incidents">Incident Response</a>
      <a href="#compliance">OFAC Compliance</a>
      <a href="#osint">OSINT Threat Intel</a>
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

      ${renderCriticalFindingsGlance(v104)}

      <div class="kpi-grid">
        <a href="#findings" style="text-decoration:none; color:inherit; display:block;">${kpiCard(ICON.alert, "Total Findings (this run)", data.metrics.totalFindings, undefined, "#38bdf8")}</a>
        <a href="#findings" style="text-decoration:none; color:inherit; display:block;">${kpiCard(ICON.shield, "Critical &amp; High (this run)", data.metrics.criticalFindings + data.metrics.highFindings, undefined, "#ef4444")}</a>
        <a href="#gates" style="text-decoration:none; color:inherit; display:block;">${kpiCard(ICON.check, "Required Gates Passing", `${data.metrics.complianceScorePct}%`, undefined, data.metrics.complianceScorePct === 100 ? "#22c55e" : "#eab308", undefined, data.metrics.complianceScorePct)}</a>
        <a href="#subsystems" style="text-decoration:none; color:inherit; display:block;">${kpiCard(ICON.server, "Active Consensus Alerts", data.metrics.activeConsensusAlerts, undefined, "#f97316")}</a>
        <a href="#forensics" style="text-decoration:none; color:inherit; display:block;">${kpiCard(ICON.lock, "Forensic Cases Sealed (this run)", data.metrics.forensicCasesSealed, undefined, "#a78bfa")}</a>
        ${kpiCard(ICON.flask, "DefectDojo Unique Flaws", ddj?.active_unique_findings ?? "N/A", "Across all historical runs — not this run's count.", "#38bdf8", "CUMULATIVE")}
        <a href="#dsomm" style="text-decoration:none; color:inherit; display:block;">${kpiCard(ICON.shield, "DSOMM Maturity", kpiDsommMaturity(), "Click to view maturity breakdown", "#8b5cf6")}</a>
        <a href="#governance-enrichment" style="text-decoration:none; color:inherit; display:block;">${kpiCard(ICON.shield, "ATT&CK/CIS/ISO Mapped", kpiGovernanceEnrichedCount(), "Click to view mapped findings", "#14b8a6")}</a>
        <a href="#stride-coverage" style="text-decoration:none; color:inherit; display:block;">${kpiCard(ICON.shield, "STRIDE Coverage", kpiStrideCoverageLabel(), "Click to view category evidence", "#eab308")}</a>
        <a href="#dread-scoring" style="text-decoration:none; color:inherit; display:block;">${kpiCard(ICON.alert, "DREAD Scored", kpiDreadScoredCount(), "Click to view per-finding vectors", "#f43f5e")}</a>
        <a href="#gitleaks" style="text-decoration:none; color:inherit; display:block;">${kpiCard(ICON.lock, "Gitleaks Secrets Found", kpiGitleaksCount(), "Click to view detections", "#dc2626")}</a>
        <a href="#lynis" style="text-decoration:none; color:inherit; display:block;">${kpiCard(ICON.server, "Lynis Hardening Index", kpiLynisHardeningIndex(), "Click to view host-compliance findings", "#0ea5e9")}</a>
        <a href="#gates" style="text-decoration:none; color:inherit; display:block;">${kpiCard(ICON.flask, "ZAP Findings", kpiZapFindings(), "High+Medium+Low alerts (excludes Info); click to view in Gate-by-Gate Status", "#06b6d4")}</a>
        <a href="#osint" style="text-decoration:none; color:inherit; display:block;">${kpiCard(ICON.server, "OSINT Check (Demo)", kpiOsintStatus(), "AbuseIPDB demonstration canary; click to view", "#0ea5e9")}</a>
      </div>

      <div id="charts" class="section-card">
        <div class="section-title"><span class="title-icon">${ICON.pulse}</span>Visual Overview</div>
        <div class="section-sub">Every chart below is drawn from this run's real fields — nothing is estimated or templated.</div>
        <div class="chart-grid">
          <div><div class="dim" style="font-size:12px; margin-bottom:6px;">Severity Breakdown</div><div class="chart-box"><canvas id="chartSeverity"></canvas></div></div>
          <div><div class="dim" style="font-size:12px; margin-bottom:6px;">Findings by Zone</div><div class="chart-box"><canvas id="chartZone"></canvas></div></div>
          <div><div class="dim" style="font-size:12px; margin-bottom:6px;">Gate Status by Policy</div><div class="chart-box"><canvas id="chartGates"></canvas></div></div>
          <div><div class="dim" style="font-size:12px; margin-bottom:6px;">Run History Trend</div><div class="chart-box"><canvas id="chartTrend"></canvas></div></div>
          <div><div class="dim" style="font-size:12px; margin-bottom:6px;">Findings by MITRE ATT&amp;CK Technique</div><div class="chart-box"><canvas id="chartAttack"></canvas></div></div>
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

      ${renderConsensusAttackSection()}
      ${renderFlashLoanSection()}

      ${renderGitleaksSection()}

      ${renderKycSection()}

      ${renderTriageClassifierSection()}
      ${renderRugpullSection()}
      ${renderHsmSection()}
      ${renderQuorumSigningSection()}
      ${renderSarDraftSection()}
      ${renderVyperSection()}
      ${renderEchidnaSection()}
      ${renderZkOfacSection()}
      ${renderNvdMirrorSection()}
      ${renderLynisSection()}
      ${renderEtherscanSection()}
      ${renderIndexerSection()}
      ${renderZkAttestationSection()}
      ${renderGovernanceEnrichmentSection()}
      ${renderStrideCoverageSection()}
      ${renderDreadScoringSection()}

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

      ${renderOsintSection()}

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

    ${
      attackLabels.length > 0
        ? `chartInstances.push(new Chart(document.getElementById("chartAttack"), {
      type: "bar",
      data: { labels: ${JSON.stringify(attackLabels)}, datasets: [{ label: "Findings", data: ${JSON.stringify(attackValues)}, backgroundColor: "${TONE_HEX.amber}", borderRadius: 4 }] },
      options: { indexAxis: "y", plugins: { legend: { display: false } }, scales: chartDefaults.scales }
    }));`
        : `document.getElementById("chartAttack").parentElement.innerHTML = '<div class="empty-note">Not run this cycle.</div>';`
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
