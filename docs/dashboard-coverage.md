# Dashboard / Tool Coverage — Real, Verified State

Last verified: 2026-10-30, live against the actual running services (not from
docstrings, compose files, or memory of earlier sessions). Every count below
was read directly from each tool's own API in this session.

**Update 2026-10-31** (Part A/B/C — Etherscan lookup + on-chain indexer):
counts re-verified live via `_cat/indices` after this session's integration
runs. `blockchain-soc-events` and `blockchain-soc-audit-logs` grew from
ordinary pipeline-run telemetry; `etherscan-lookup`'s own event category was
confirmed landing in `blockchain-soc-events` once the real Vault key was
seeded (see below) — the biggest new growth is the third index below.

**Update 2026-10-31, later same day** (Part 0 — contract fixture rewrite):
`VulnerableVault.sol`/`SecureVault.sol` rewritten with 8 new mirrored
vulnerability/fix pairs (unchecked-call, integer-overflow, tx-origin,
missing-access-control, controlled-delegatecall, suicidal, timestamp,
calls-loop) so every SAST/symbolic phase gets real, multi-class signal, not
just the pre-existing reentrancy/flash-loan/rug-pull surface. Confirmed live
via two full `make pipeline-all` runs (vulnerable + secure):
- Slither: VulnerableVault 21 findings (4 High/3 Medium/8 Low/4 Info/2 Opt,
  14 detector classes) vs. SecureVault 16 findings (0 High/Medium, all
  Low/Info/Opt).
- Mythril: VulnerableVault 7 issues (SWC-115 tx-origin ×6, SWC-106
  unprotected-selfdestruct ×1) vs. SecureVault 2 low-severity env-dependence
  notes only, no high-severity SWC hits.
- `rugpull-detector`: 2 failing checks on VulnerableVault (confirmed live
  via its own `reports/scanners/rugpull-detector.json` and a matching
  DefectDojo finding), 0/not-applicable on SecureVault. **A real bug was
  found and fixed in this process**: the first draft named a new function
  `timeLockedBonus`, whose lowercase substring `timelock` accidentally
  matched `rugpull_detector.py`'s `TIMELOCK_RE`, flipping
  `missing_ownership_protection` from FAIL to PASS on VulnerableVault
  (observed live: `failing_checks` dropped from 2 to 1 on the first
  post-rewrite run). Renamed to `luckyBlockBonus`, recompiled, and
  re-verified live (`failing_checks` back to 2) before accepting the result.
- `AVS consensus`, both Echidna harnesses, and the `sast-canary` differential
  all confirmed unaffected (they only ever call `deposit()`/`withdraw()`/
  `balances`, which were left byte-for-byte untouched).
- `scripts/ingest-manifests.mts`, `scripts/ast-mask.mts`, and
  `scripts/run-formal-tools.cjs`'s pinned sha256 hashes for both contract
  files were updated to match; Zone 1 manifest ingestion and AST masking
  both confirmed passing live with the new hashes before any full run.

## Elasticsearch + Kibana

Three real indices now exist, all project-specific (confirmed via `_cat/indices`):

| Index | Real doc count (2026-10-30) | Real doc count (2026-10-31) |
|---|---|---|
| `blockchain-soc-events` | 2,451 | 3,161 |
| `blockchain-soc-audit-logs` | 137 | 148 |
| **`blockchain-soc-onchain-events`** (new 2026-10-31, Part B) | n/a | 27 (3 indexer runs × 9 real docs each — 1 standalone test + Part C's run3/run4) |

`blockchain-soc-events`' real `event_category` breakdown (via a live terms
aggregation), mapped to the pipeline step that produces it:

| event_category | docs | pipeline step |
|---|---|---|
| dast-alert | 681 | ZAP (`scripts/run-dast.sh`) |
| ai-swarm | 504 | LangGraph swarm (`src/agents/swarm_orchestrator.py`) |
| secret-leak | 340 | Gitleaks (`scripts/run-secret-scan.sh`) |
| vulnerability | 304 | Slither + Mythril, both tagged into this one category (`scripts/run-sast-symbolic.py`) |
| avs-consensus | 216 | `src/consensus/avs_consensus.py` |
| consensus-attack | 189 | `src/consensus/chain_attack_monitor.py` |
| container-trivy | 44 | Trivy (`scripts/run-trivy.sh`) |
| defi-rugpull | 26 | `src/defi/rugpull_detector.py` |
| echidna-fuzzing | 25 | `scripts/run-echidna.sh` |
| vyper-check | 25 | `scripts/run-vyper-check.py` |
| ofac-screening | 22 | `scripts/run-ofac-screening.py` |
| readiness-gate | 22 | `scripts/run-readiness-gate.sh` |
| sca-dependency | 22 | `scripts/run-sca-gate.py` |
| defi-flashloan / defi-frontrunning | 13 / 13 | `src/defi/flashloan_detector.py` |
| **kyc-screening** | 2 | `scripts/run-kyc-screening.py` — **wired this session** (was 0) |
| k8s-k3s | 1 | inline k3s check, `run-all-e2e.sh` |
| quorum-signing | 1 | `src/wallet/quorum_signer.py` |
| **triage-classifier** | 1 | `scripts/run-triage-classifier.py` — **wired this session** (was 0) |
| **etherscan-lookup** | pending real-key seeding | `scripts/run-etherscan-lookup.py` — **wired 2026-10-31** (Part A); event only emitted once `secret/data/soc/etherscan` is seeded in Vault |

`compliance-openscap` and `code-quality-sonar` categories exist in
`ingest-granular-siem.py`'s code but have **zero real docs ever** — this is
real, not an oversight: both are alert-on-failure-only, and neither tool has
ever genuinely failed in a recorded run (openscap never scores a rule on this
host at all; sonar's quality gate has never gone ERROR).

### New dedicated index: `blockchain-soc-onchain-events` (Part B, added 2026-10-31)

The real on-chain indexer (`src/onchain/indexer.py`, wired as `scripts/run-indexer.py`
in Zone 1) writes decoded events and raw transaction-activity documents into
**its own dedicated index**, deliberately NOT mixed into `blockchain-soc-events`
(which is pipeline-run telemetry, a different shape). Confirmed live, first
standalone run: 9/9 real documents indexed (5 decoded events from
`DeFiLendingVault`/`StakingRewardsVault`, 4 transaction-activity docs from
`VulnerableVault`/`SecureVault`, which emit no events at all — verified by
source inspection, not assumed). See `src/onchain/indexer.py`'s own HONEST
SCOPE note for exactly what this is (a short-lived per-run indexing pass
against its own ephemeral Anvil) and is not (a persistent daemon; a
subscription to `avs_consensus.py`'s own already-torn-down nodes).

This index has no Kibana saved objects of its own yet — its data is
genuinely time-series/volume-shaped (per-run event counts), so it is
exported to Grafana/Prometheus instead (see below), consistent with
`docs/dashboard-coverage.md`'s own existing rule that Grafana, not Kibana,
is this project's trend-shaped dashboard.

**Kibana dashboards** (2 real `dashboard` saved objects exist):
- `autonomous-blockchain-soc-master` ("Enterprise Autonomous Blockchain SOC —
  SIEM Center") is the live one, embedding 8 panels: `soc-total-events`,
  `soc-tool-distribution`, `soc-severity-distribution`,
  `soc-category-breakdown`, `soc-event-velocity`, `soc-swarm-verdicts`, and
  two saved searches (`soc-live-events-grid`, `soc-sections-a-c-events`).
- The 5 breakdown/distribution panels are generic terms-aggregations over
  `event_category.keyword` / `tool_name.keyword` / `log_level.keyword` —
  schema-driven, so `kyc-screening` and `triage-classifier` now appear on
  them automatically, with no panel changes needed (confirmed live by
  replaying their exact aggregation against the real index).
- `soc-sections-a-c-events` is a **hardcoded category allowlist** (title:
  "Sections A-G + Pre-Existing Scanners: Full New Detector Coverage") that
  did NOT include `kyc-screening` or `triage-classifier` — **fixed this
  session** via the Kibana saved-objects API; confirmed live that 3 real
  docs (2 kyc-screening, 1 triage-classifier) now match its updated query.
- **`etherscan-lookup` added to the same `soc-sections-a-c-events` allowlist
  on 2026-10-31** (Part A/C) — confirmed live via the Kibana saved-objects
  API that the updated query string now includes it (PUT applied, re-read
  back and verified before moving on). This event will only start landing
  in `blockchain-soc-events` once `secret/data/soc/etherscan` is seeded in
  Vault with a real key (pending as of this writing).
- `avs-consensus` and `ai-swarm` are the only two steps with a bespoke
  dedicated chart (`soc-consensus-donut`, `soc-swarm-verdicts`).
  `ofac-screening` — the reference pattern this session matched KYC against
  — has **no bespoke chart either**, only the generic panels + the
  catch-all search. KYC's real coverage now matches OFAC's exactly, which is
  the correct, non-overbuilt target, not an oversight.

## DefectDojo

Verified live via its real `/api/v2/findings/` and `/api/v2/tests/` API
(778 real tests recorded). A fresh real ingestion run this session confirms:

| Step | Confirmed in DefectDojo |
|---|---|
| trivy, zap, slither, mythril, sca, readiness, avs-consensus, swarm, ofac-screening, **kyc-screening**, sar-draft, consensus-attack, flashloan-detector, **triage-classifier**, rugpull-detector, echidna, vyper-check | YES — real `uploaded=[...]` list from this session's `ingest-defectdojo.py` run |
| sonar | YES, but "clean" this run (ran ok, 0 findings to report) |
| openscap | code path exists but **skipped** this run (openscap's own status wasn't ok) |
| gitleaks | YES, via a separate hardcoded SARIF/JSON import path (not the generic list) — 51 real `Gitleaks Scan` test runs, 3,209 real findings recorded historically |
| **indexer** (added 2026-10-31, Part B/C) | YES — confirmed live via DefectDojo's own `/api/v2/findings/` on both Part C runs ("On-Chain Indexer: 9 Document(s) Indexed", severity Info, present both times) |
| **etherscan-lookup** (added 2026-10-31, Part A/C) | Code path added (`build_etherscan_findings()`); not yet confirmed uploaded end-to-end — pending `secret/data/soc/etherscan` being seeded with a real key |

`triage-classifier`'s finding ("ML Triage Hint: Front_running (Most-Similar
DASP Category)", severity Info) and `kyc-screening`'s finding ("OpenSanctions
KYC Match (CONFIRMED): Lazarus Group", severity Critical) were both
individually confirmed present via a direct title search against the live
API in this session — not just inferred from the ingestion script's own exit
message.

## Every other real dashboard found in the integration audit

| Tool | Port | What this pipeline's data it shows |
|---|---|---|
| **Grafana** | 3000 | The one real provisioned dashboard (`config/grafana-gen/blockchain-soc-full-coverage-dashboard.json`) is confirmed, by reading its own generator script, to be **100% Prometheus-metric-shaped**: DSOMM maturity, Trivy/Slither/Mythril counts, consensus-attack/flashloan/rugpull/vyper/echidna counts, HSM/quorum signer status, swarm verdicts. **KYC, OFAC, and triage-classifier are genuinely not applicable here** — none of the three are exported as Prometheus metrics (confirmed: zero `ofac`/`kyc`/`triage` references in `scripts/ship-siem-telemetry.py`), because a per-name/per-contract screening or prediction result isn't gauge-shaped data the way a scan count is. Forcing a fake metric export for these would misrepresent their real shape. OFAC — the reference step — gets no Grafana panel either, confirming this isn't a KYC-specific gap. **Added 2026-10-31 (Part B/C)**: a new real `timeseries` panel ("Indexed Document Count Over Time, by Type") was added to this same dashboard, backed by a new real gauge pair (`blockchain_soc_indexer_documents_indexed{doc_type=...}`) exported by `scripts/ship-siem-telemetry.py` — confirmed live via Prometheus's own `/api/v1/query` (`decoded_event`=5, `transaction_activity`=4 after the first standalone indexer run), then deployed to `/srv/devsecops/grafana/provisioning/dashboards/` and confirmed live via Grafana's own `/api/dashboards/uid/blockchain-soc-full-coverage` (version bumped 2026-10-31; 29 panels total, including the new row and `timeseries` panel, both genuinely present in the API response, not just the local JSON file). Unlike KYC/OFAC/triage-classifier, the indexer's per-run document counts genuinely are gauge/trend-shaped (a real count that changes run-over-run), which is why this one got a bespoke panel where those three correctly did not. |
| **Prometheus** | 9090 | Backs Grafana directly; same scope (DSOMM + scan-count gauges), scraped from `:9101/metrics`. Not applicable to KYC/triage-classifier, same reasoning as Grafana. |
| **SonarQube** | 9000 | Real quality-gate status for this repo's own JS/TS/Python scripts (confirmed via `pipeline-verdict.py`'s own real detail text: "Community Edition: Solidity not analysed; scripts only"). Does not scan Solidity contracts and has no concept of KYC/OFAC/triage-classifier findings — not applicable. |
| **TheHive** | 9005 | Real incident-case creation on a HALT verdict (`scripts/run-incident-abort.py` → `ingest-thehive-incident.py`), confirmed live and up in this session's earlier audit (Cortex connector shows `ERROR`, TheHive itself does not). Case content is the pipeline's HALT reason text, not per-finding detail — KYC/triage-classifier would only appear here if they were ever a HALT reason, which neither is designed to be. |
| **Langfuse** | 3100 | Real LLM trace spans capturing the swarm/AVS reasoning for a run (`scripts/langfuse_tracer.py`), confirmed live and healthy earlier this session. Not applicable to KYC/triage-classifier (neither involves an LLM call). |
| **MLflow** (added this session) | 5000 | Real Docker container (`docker/docker-compose.mlflow.yml`, `ghcr.io/mlflow/mlflow:v3.17.2`), backend store + artifact root on a named volume (`mlflow_data`) so run history survives a restart. Owns exactly the ML-specific history none of the other tools cover: the `triage-classifier-training` experiment logs real params (dataset commit, n, hyperparameters), metrics (CV accuracy/macro-F1/per-class scores/95% CI), and artifacts (the `.joblib`, a real confusion-matrix PNG, a real feature-importance PNG) on every training run; the `triage-classifier-inference` experiment logs one real run per live scan (target contract, predicted category, top-3 probabilities, and the exact training-run ID that produced the scoring model). Deliberately does NOT duplicate the per-run prediction+confidence view -- that stays in the HTML report / DefectDojo / Kibana, which are better suited to live SOC alerting; MLflow is the answer to "how was this model trained" and "has retraining ever changed its accuracy," not "what did today's scan say." |
| **Vault** | 8200 | Real Transit-engine attestation signatures over the pipeline run's verdict, confirmed live (`sys/health` healthy, `initialized=true`, `sealed=false`). Infra/signing only — not applicable to findings data. |
| **Argo CD** | 30979 (NodePort; the `:8080` seen in `launch-soc-ui.sh` is a manually-left-running `kubectl port-forward`, not a persistent config) | GitOps manifest reconciliation only (`config/k8s/argocd-app.yaml`/`argocd-project.yaml`); no pipeline script pushes findings data to it. Not applicable. |
| **Jenkins** | 8082 | A standalone connectivity/auto-heal check (`scripts/orchestrate-enterprise-integrations.sh`), a separate entry point from `run-all-e2e.sh`. Carries no pipeline findings data. Not applicable. |
| **GitLab** | 8929 | Hosts this repo's own git remote (`gitlab-soc`). No pipeline script ships findings there. Not applicable. |

## Local HTML report (`reports/latest.html`)

Cross-referenced against every Part A step from the integration audit, after
Tasks 1-3's fixes:

```
slither: 5        mythril: 1        sast-canary: 0*   trivy: 0*
zap: 0*           sca: 3            sonar: 0*         openscap: 4
readiness: 0*     avs-consensus: 0* swarm: 9          ofac-screening: 0*
consensus-attack: 5   flashloan: 4  rugpull: 4        echidna: 6
vyper-check: 1    kyc-screening: 5  triage-classifier: 4   dsomm: 19
gitleaks: 7
```

`*` = no dedicated section, but confirmed present (live, via the regenerated
`reports/latest.html`) in the generic **Gate-by-Gate Status** table, which
reads every `reports/scanners/*.json` directly — these are the REQUIRED
pipeline-health gates (trivy/zap/sonar/sca/readiness/openscap/slither/mythril/
sast-canary) plus avs-consensus/ofac-screening, all already given a proper
per-finding home in DefectDojo (confirmed above), so a redundant per-tool
breakout table in the static HTML report was judged unnecessary scope beyond
what Task 3 asked — a deliberate call, not an oversight.

**Real gaps found and fixed this session:**
- `gitleaks` had **zero** HTML presence beyond the generic gate row — added
  a dedicated section (`#gitleaks`) with real per-secret rows, secret values
  redacted (first/last 4 characters only — the raw report contains real
  working secret values and this report may be archived/shared).
- `kyc-screening` only surfaced via the generic Master Findings Register,
  losing its own confidence/review-status detail — added a dedicated
  section (`#kyc-screening`) matching OFAC's shape, plus the real
  CONFIRMED/INCONCLUSIVE/NO_MATCH confidence badge and DraftKycReview
  review-status badge OFAC has no equivalent of.

Every other step (consensus-attack, echidna, vyper-check, avs-consensus,
swarm, flashloan, rugpull, triage-classifier, dsomm) already had a real,
populated dedicated section — confirmed by checking each one actually
renders real content on this run, not an empty-state placeholder.

## Combined table — where to look for each pipeline step

| Pipeline step | One-off finding | Historical/trend view | Last verified |
|---|---|---|---|
| slither, mythril | HTML report `#findings`; DefectDojo | HTML `#trend` sparkline; DefectDojo cumulative count | 2026-10-30 |
| trivy, zap, sca, sonar, openscap, readiness, sast-canary | HTML report Gate-by-Gate table; DefectDojo | DefectDojo cumulative count | 2026-10-30 |
| avs-consensus | HTML `#findings` + dedicated AVS panel; DefectDojo | Kibana `soc-consensus-donut` | 2026-10-30 |
| swarm | HTML dedicated LangGraph panel; DefectDojo | Kibana `soc-swarm-verdicts` | 2026-10-30 |
| consensus-attack | HTML `#consensus-attack`; DefectDojo | Kibana generic breakdown panels; Grafana (count only) | 2026-10-30 |
| flashloan, rugpull | HTML `#flashloan`; DefectDojo | Kibana generic breakdown panels; Grafana (count only) | 2026-10-30 |
| echidna, vyper-check | HTML `#echidna` / `#vyper`; DefectDojo | Kibana generic breakdown panels; Grafana (count only) | 2026-10-30 |
| **gitleaks** | **HTML `#gitleaks` (new this session)**; DefectDojo (separate SARIF path) | Kibana `secret-leak` category (generic panels); Grafana `blockchain_soc_gitleaks_findings` | 2026-10-30 |
| **ofac-screening** | HTML `#compliance`; DefectDojo | Kibana generic breakdown panels + catch-all search | 2026-10-30 |
| **kyc-screening** | **HTML `#kyc-screening` (new this session)**; DefectDojo | **Kibana generic breakdown panels + catch-all search (fixed this session)** | 2026-10-30 |
| **triage-classifier** | HTML `#triage-classifier`; DefectDojo | **Kibana generic breakdown panels + catch-all search; MLflow (training history/dataset lineage/confusion matrix -- added this session, see below)** | 2026-10-30 |
| dsomm | HTML DSOMM section | **Grafana/Prometheus (the one step already correctly trend-shaped)** | 2026-10-30 |
| sar-draft, presign-sim, vault-sign, k3s, hsm-signer, quorum-signer, langfuse | HTML `#findings` or infra panels; DefectDojo (sar-draft only) | Kibana (alert-on-failure-only — only non-ok runs ever produce a doc) | 2026-10-30 |

Grafana/Prometheus columns above are marked "(count only)" where the real
provisioned dashboard tracks a single gauge/count for that step rather than
per-item detail — the per-item breakdown for those always lives in
DefectDojo or Kibana's generic panels, not Grafana.
