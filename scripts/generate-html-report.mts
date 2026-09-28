// TODO(phase-14): Zone 9 — port your existing generate-html-report.mts
// tool here, then extend it per blueprint Section 4E.4/4E.5.
//
// ALREADY BUILT (port as-is, do not rebuild):
//   - deep-space dark theme, CSS custom properties, Inter + JetBrains Mono
//   - sticky sidebar navigation (IntersectionObserver)
//   - inline SVG charts: donut, bar, confusion matrix
//   - 20+ icon library, no CDN dependency
//   - toolbar: live search, severity/tool/status filter pills, column
//     toggles, CSV export of visible rows, toast notifications
//   - print system (window.print(), wide-table-to-card layout for PDF)
//   - 21-column Compliance Register (ZKP flags as colored pill triads,
//     source signals as labeled dots), NormalizedComplianceRow type
//
// NEW IN THIS PROJECT (add on top of the ported tool):
//   - Consensus Attack panel (Zone 6): alert count, type breakdown,
//     AVS-confirmed vs rejected
//   - Wallet Audit panel (Zone 7): findings by vulnerability class,
//     key-scheme coverage (Shamir/HSM/MPC status)
//   - Forensic Case Timeline panel (Zone 5): case count, status,
//     REDACTED summaries only — never raw evidence
//   - Executive KPI cards (findings by severity, open cases, alert
//     count, compliance pass rate, benchmark P/R/MTTR)
//   - Auto-generated Pros/Strengths, Cons/Flaws, and Recommended Actions
//     (templated per finding type)
//   - One new chart: consensus-alert timeline (Zone 6)
//
// Input: status.json (produced by aggregate-status.mts)
// Output: one self-contained reports/project-status-<timestamp>.html —
//   no server, no login, no external dependency.
export async function generateHtmlReport(_statusJsonPath: string): Promise<string> {
  throw new Error("not implemented — see checklist Phase 14");
}
