# Autonomous AI-Native Blockchain Security SOC — Project Skeleton (V10.3)

This is the **skeleton scaffold** for the Enterprise V10.3 blueprint (V10.2's
Zones 1-8 plus Zone 9: the Unified Executive HTML Report Layer, which rolls
up every zone's status into one front-page report). Aligned to Topic 124
(EduQual Level 6, Code ANPP-OP) — all 6 required topic areas have a
corresponding folder in this skeleton, and Zone 9 makes their results
visible in one place.

Every folder and stub file below corresponds to a specific zone or module
in the blueprint / implementation checklist. Nothing here is
production-complete — each file has a `TODO(phase-N)` comment pointing at
the checklist phase that fills it in. Build in phase order; don't jump
ahead.

## Layout

```
contracts/                 Zone 1 — target Solidity/Vyper contracts to audit
contracts/solidity/wallets/  Zone 7 — sample wallet contracts for wallet-audit testing [NEW]
move/                       Zone 1 — target Move packages/modules to audit
test/                       Zone 1/2 — Foundry & Hardhat test layouts
test/forensics/             Zone 5 — integrity, custody-chain, OPA-deny, sanitizer tests
test/consensus_security/    Zone 6 — detector accuracy + false-alert tests [NEW]
test/wallet_security/       Zone 7 — key-policy denial tests [NEW]
test/compliance/            Zone 8 — policy denial + ZK-proof correctness tests [NEW]
scripts/                    Zone 1-4 — pipeline entrypoints (ingest, sca, orchestrator)
src/llm_client/             Transport bridge — Ollama router (Windows GPU host)
src/agents/                 Inference layer — Agents A-G + escalation + Upgrade 5 [NEW]
src/mcp_middleware/         Zone 3 — MCP tool servers (anvil sandbox, forensics,
                             consensus-monitor, wallet-audit, compliance-screen)
src/consensus/              AVS BFT attestation gate
src/consensus_security/     Zone 6 — P2P listener, reorg monitor, concentration
                             tracker, selfish-mining + eclipse detectors [NEW]
src/wallet_security/        Zone 7 — Shamir, HSM client, MPC relayer,
                             pre-signing simulator [NEW]
src/compliance/             Zone 8 — address screener, AML patterns, ZK
                             attestation, SAR report generator
src/reporting/               Zone 9 — package marker for the report layer [NEW]
reports/                     Zone 9 — generated HTML status reports land here,
                             gitignored by default [NEW]
src/storage/                Zone 3 — SQLite/Redis broker, normalize/enrich pipeline
src/observability/          Prometheus/ELK hooks + RASP shield
src/mitigation/              Zone 4 — incident orchestrator, egress gateway
src/forensics/               Zone 5 — acquisition, integrity, evidence vault, etc.
config/                     foundry.toml, hardhat.config.js, Move.toml, OPA policies
config/opa/                 agent_policy.rego, forensics_policy.rego,
                             consensus_policy.rego, wallet_policy.rego,
                             compliance_policy.rego [3 NEW]
dashboard/                  Vercel/Next.js live SOC dashboard (Track B)
docs/                       IEEE/ACM paper draft, benchmark tables (Track A),
                             forensic-report-template.md
scripts/aggregate-status.mts       Zone 9 — rolls up Zones 1-8 + benchmarks into status.json [NEW]
scripts/generate-html-report.mts   Zone 9 — port of your existing HTML report tool, extended [NEW]
.gitlab-ci.yml              Pipeline definition — stages: consensus-security,
                             wallet-security, compliance, report [NEW]
```

## Build order

Follow `implementation-checklist-v10.2.pdf` phase by phase:

Phase 0 (env, incl. Zone 6-8 tooling) → Phase 1 (this skeleton) →
Phase 2 (Zone 1) → Phase 3 (Zone 2, incl. Upgrade 5 stubs) →
Phase 4 (Zone 3) → Phase 5 (Inference + Agents) → Phase 6 (AVS Consensus) →
Phase 7 (Deploy/Abort) → Phase 8 (Observability/RASP) → Phase 9 (Zone 4) →
Phase 10 (Zone 5 — Forensics) →
**Phase 11 (Zone 6 — Consensus Attack Detection, NEW)** →
**Phase 12 (Zone 7 — Wallet & Key Management, NEW)** →
**Phase 13 (Zone 8 — Compliance Automation, NEW)** →
**Phase 14 (Zone 9 — Unified Executive HTML Report, NEW)** →
Phase 15 (Benchmarks, dashboard, docs, video/LinkedIn).

## Topic 124 coverage (this skeleton)

| Required area | Skeleton folder |
|---|---|
| AI-Powered Smart Contract Auditing | `src/agents/agent_a_auditor.py`, `agent_d_red_teamer.py` |
| DevSecOps for Blockchain | `.gitlab-ci.yml`, `scripts/`, `config/` |
| DeFi Protocol Security & Attack Prevention | `src/agents/upgrade5_defi_attacks.py` |
| Consensus Attack Detection & Prevention | `src/consensus_security/` |
| Wallet & Key Management Security | `src/wallet_security/` |
| Compliance & Regulatory Automation | `src/compliance/` |

Zone 9 (`src/reporting/`, `scripts/aggregate-status.mts`,
`scripts/generate-html-report.mts`) is not itself one of the 6 required
areas — it's the reporting layer that shows all 6 areas' results in one
HTML file. Worth naming explicitly as your project's "front page" in a
presentation.

## What changed from the V10.2 skeleton

- Added `src/reporting/` (package marker), `scripts/aggregate-status.mts`
  (rolls up Zones 1-8 + Upgrade 3 benchmarks into one `status.json`), and
  `scripts/generate-html-report.mts` (a port point for your existing
  HTML report tool — dark theme, SVG charts, 21-col Compliance Register,
  search/filter/CSV toolbar, print-to-PDF — extended with a Consensus
  panel, Wallet Audit panel, Forensic Case Timeline panel, Executive KPI
  cards, and auto-generated Pros/Cons/Recommendations).
- Added `reports/` (gitignored by default — internal artifact, not
  auto-published) and `test/reporting/` (3 test stubs).
- `.gitlab-ci.yml`: added a `report` stage that regenerates the HTML
  report at the end of every pipeline run.
- `package.json`: added an `npm run report` script.
- `Makefile`: added a `status-report` target.
- Nothing from V10.2 was removed or renamed. Only the old Phase 14
  (Benchmarks) was renumbered to Phase 15 to make room for the new
  Phase 14 (Zone 9).

## What changed from the V10.1 skeleton

- Added `src/consensus_security/` (5 modules), `src/wallet_security/`
  (4 modules), `src/compliance/` (4 modules).
- Added `src/mcp_middleware/consensus_monitor.py`, `wallet_audit.py`,
  `compliance_screen.py`.
- Added `src/agents/upgrade5_defi_attacks.py` (front-running, rug-pull,
  flash-loan detection) — has a documented forward dependency on Zone 6's
  mempool feed, built in Phase 11.
- Added `config/opa/consensus_policy.rego`, `wallet_policy.rego`,
  `compliance_policy.rego`.
- Added `contracts/solidity/wallets/` for sample wallet-audit contracts.
- Added `test/consensus_security/`, `test/wallet_security/`,
  `test/compliance/` (8 test stubs total).
- `.gitlab-ci.yml`: added `consensus-security`, `wallet-security`, and
  `compliance` stages (all scheduled/continuous, not per-commit, except
  wallet-audit which also triggers on wallet-contract changes).
- `docker-compose.yml` / `requirements.txt`: TODOs and commented
  dependencies added for all three new zones.
- Nothing from V10.1 was removed or renamed. All prior TODO(phase-N)
  numbers for Zones 1-5 are unchanged; only the old Phase 11 (Benchmarks)
  was renumbered to Phase 14 to make room.
