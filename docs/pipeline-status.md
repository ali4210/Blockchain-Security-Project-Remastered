# Pipeline Status — Standing Reference for Future Sessions

**Last updated:** 2026-11-05 (after wiring governance-framework enrichment,
the STRIDE coverage scorecard, and 5-factor DREAD scoring into the HTML
report)
**Based on:** the two post-Part-0 contract-rewrite runs
(`reports/audit/run3-vulnerable-postintegration.log`,
`reports/audit/run4-secure-postintegration.log`) plus two further runs that
confirmed both Gap Fixes live and regression-free
(`reports/audit/run5-zk-attestation-check.log` — VulnerableVault,
`HEALTH: OK`, `VERDICT: HALT`, `contract_verdict: FAIL` — and
`reports/audit/run6-secure-gapfix-check.log` — SecureVault, `HEALTH: OK`,
`VERDICT: HALT`, `contract_verdict: PASS`), plus three further full
`make pipeline-all` runs on 2026-11-05 (VulnerableVault throughout) that
confirmed, in order: governance-framework enrichment live (`HEALTH: OK`,
`VERDICT: HALT`, 859–1154s), the STRIDE coverage scorecard live (same
verdict; one run ran 22588s due to an unrelated local-Ollama stall in the
LangGraph swarm step — localized by file-mtime gap, not caused by this
work), and 5-factor DREAD scoring live (859s, back to normal). Both
contracts were rewritten earlier the same week (Part 0) to add 8 new
mirrored vulnerability/fix pairs; both Etherscan lookup (Part A) and the
on-chain indexer (Part B) are live and working with a real seeded Vault
key.

**How to use this file:** you (a future Claude session, in chat or
terminal, with no memory of today) should treat every verdict below as a
starting point to RE-VERIFY live, not a fact to repeat from memory — this
project's own operating discipline is "no claim without a live command or
API response backing it." Don't suggest re-adding anything in the
"deliberately not integrated" section without reading why first.

Verdict legend: **STRONG** (fully live, real, verified) | **PARTIAL**
(real but limited/simulated/stubbed — reason given) | **GAP** (not present,
or present but disconnected from the live pipeline).

---

## Zone 1 — Manifest, secrets, deployed-artifact intelligence

| Component | What it checks | Verdict | Why |
|---|---|---|---|
| `scripts/ingest-manifests.mts` | Strict Foundry/Hardhat/Move manifest + asset-map integrity, sha256-pinned per file | STRONG | Confirmed passing live with both contracts' post-rewrite hashes |
| `scripts/run-secret-scan.sh` (gitleaks) | Real high-entropy secret scan of the working tree | STRONG | Real `gitleaks detect`, 7 known findings every run (deferred — rotation parked; includes a well-known public Anvil dev key flagged in `indexer.py`, a real finding but not a real secret) |
| `scripts/run-etherscan-lookup.py` | Real Etherscan V2 API: verification/source, creation, balance, tx/log history for a deployed address | **STRONG** | Real Vault-seeded key confirmed live both runs: `verified=True`, real balance, 10 real tx + 25 real logs fetched for WETH9 (demonstration canary — no funded Sepolia deployer key exists for this project's own contracts, so a real public contract proves the integration instead) |
| `src/onchain/indexer.py` / `scripts/run-indexer.py` | Real on-chain indexer: deploys fixtures to its own ephemeral Anvil, generates real transactions, decodes real events, indexes into Elasticsearch | **STRONG** (scoped) | Confirmed live, 4 total runs this week: 9/9 real docs every time (5 decoded events from `DeFiLendingVault`/`StakingRewardsVault`, 4 transaction-activity docs from `VulnerableVault`/`SecureVault`, which emit no events by design). Genuinely a short-lived per-run pass, NOT a persistent daemon, NOT a hook into `avs_consensus.py`'s own (already torn-down) nodes |

## Zone 2 — SAST/symbolic/dependency/DAST gates

| Component | What it checks | Verdict | Why |
|---|---|---|---|
| Slither + Mythril (`scripts/run-sast-symbolic.py`) | Real static + symbolic analysis, differential canary | **STRONG** | Post-Part-0 rewrite confirmed live: VulnerableVault 21 Slither findings (4 High/3 Medium/8 Low/4 Info/2 Opt, 14 detector classes incl. reentrancy-eth, controlled-delegatecall, suicidal, tx-origin, unchecked-lowlevel, calls-loop, timestamp, weak-prng) + 7 Mythril issues (SWC-115 ×6, SWC-106 ×1); SecureVault 16 Slither findings (0 High/Medium, all Low/Info/Opt) + 2 low-severity Mythril env-dependence notes only |
| Mythril timeout flake | — | PARTIAL (known, pre-existing) | Intermittent wall-clock timeout, not related to the Part 0 rewrite; did not recur in the final two runs |
| ML triage classifier | scikit-learn hint layered on Slither findings | PARTIAL | Real model (n=143 LOOCV, accuracy=0.615); prediction shifted from `front_running` to `bad_randomness` after the Part 0 rewrite — a genuine, organic consequence of richer real findings, not forced |
| Echidna fuzzing | Real property-based fuzzing, both harnesses | STRONG | Confirmed unaffected by Part 0 — the harness only calls `deposit()`/`withdraw()`/`balances`, left byte-for-byte untouched |
| Flash-loan / front-running detector | Real solc-AST-based detection | STRONG | Live differential confirmed: VulnerableVault 1 flash-loan + 1 front-running finding; SecureVault 0/0 ("clean" in DefectDojo) |
| Rug-pull detector | Real pattern checks | STRONG | Live differential confirmed: VulnerableVault 2 failing checks; SecureVault 0 ("clean" in DefectDojo). **A real bug was found and fixed during Part 0**: a first-draft function name `timeLockedBonus` accidentally matched `rugpull_detector.py`'s `TIMELOCK_RE` substring check, silently flipping `missing_ownership_protection` from FAIL to PASS on VulnerableVault (observed live: count dropped from 2 to 1). Renamed to `luckyBlockBonus`, recompiled, re-verified live before accepting any result |
| SCA / Trivy / ZAP / OpenSCAP / SonarQube / readiness gate | Dependency/host/web/quality/policy scans | STRONG (SCA/Trivy/ZAP/readiness/Sonar), PARTIAL by design (OpenSCAP: 0/777 rules ever scored on this host, platform mismatch) | All confirmed live, identical real results across both final runs (project-wide, not contract-specific) |

## Zone 3 — Threat intel, swarm, consensus

| Component | What it checks | Verdict | Why |
|---|---|---|---|
| 7-agent LangGraph swarm | Real Ollama model votes over real findings | STRONG | Confirmed live: 7/7 HALT ("multiple critical vulnerabilities including reentrancy", over 28 SAST findings) on Vulnerable; 7/7 CLEAR ("all identified issues are low-severity") on Secure — qualitatively richer reasoning after Part 0's rewrite |
| AVS consensus (3-node Anvil BFT) | Real exploit execution + trace inspection | STRONG | Confirmed live, unaffected by Part 0: 3/3 EXPLOIT_CONFIRMED (Vulnerable), 3/3 CLEAN (Secure) |
| P2P listener | Real propagation/ASN-diversity engine | PARTIAL | One hardcoded demo peer in the hot path — no real P2P mesh exists |
| Consensus-attack monitor | Real forced Anvil reorg + real detector math | PARTIAL | Single-node devnet; fires identically regardless of target (by design, documented) |
| OFAC / KYC screening | Real SDN / OpenSanctions snapshots | STRONG | Live, correct flag/clean both runs |
| Simplified-ZK compliance attestation (`scripts/run-zk-attestation.py`, wired 2026-10-31) | Real commitment/Merkle/challenge-response proofs over THIS run's own OFAC-screened addresses | **STRONG** (real scheme, honestly labeled) | Confirmed live on BOTH contracts (identical, since OFAC screening is project-wide): 1 real proof generated + independently re-verified (with and without the private witness), 1 correctly REFUSED for the real Lazarus Group sanctioned address, against the real 506-address OFAC SDN universe. Confirmed live in DefectDojo via its own API (4 cumulative real findings across both runs). **Explicitly NOT a zk-SNARK/STARK** — every report/HTML label says so; `src/compliance/zk_attestation.py` itself is unmodified, only newly invoked. The private witness (blinding factors) is never written to disk |
| Per-contract security verdict (`scripts/pipeline-verdict.py`'s new `contract_verdict` field, added 2026-10-31) | A real, additive classification of HALT reasons into contract-scoped (SAST differential, AVS consensus, swarm, flashloan-detector, rugpull-detector) vs. project-scoped (trivy/sca/sonar/zap/readiness), computed in a fully separate code path that never touches the existing gate | **STRONG** | Confirmed live, both contracts: VulnerableVault → `contract_verdict: FAIL` with exactly 5 contract-scoped reasons; SecureVault → `contract_verdict: PASS`, `contract_halt_reasons: []`. **Regression-checked**: both runs' pre-existing `health`/`verdict`/`gitops_allowed`/`halt_reasons` fields are byte-identical to the pre-change runs (run3/run4) — zero change to existing gate behavior. Surfaced in both `reports/verdict.json` and the console output as a clearly separate "CONTRACT-SPECIFIC SECURITY VERDICT" line |

## Zone 9 — Executive reporting: governance/threat-model enrichment (wired 2026-11-05)

All three rows below were identified as real-code-but-unwired gaps in a dedicated 8-framework audit (STRIDE/DREAD/OWASP/MITRE ATT&CK/OSINT/CIS/ISO 27001/Metasploit), then wired one at a time, each confirmed with its own standalone test, a deliberate failure-path test, and a full `make pipeline-all` run. All three are purely additive reporting metadata: new steps in `run-all-e2e.sh`'s Zone 9 block, each `|| true`, none in `pipeline-verdict.py`'s `REQUIRED` list, none able to affect `health`/`verdict`/`gitops_allowed`/`halt_reasons`/`contract_verdict`/`contract_halt_reasons` (regression-checked: those six fields were byte-identical across all three runs below).

| Component | What it checks | Verdict | Why |
|---|---|---|---|
| Governance-framework enrichment (`scripts/run-enrichment.mts`, new, calls the pre-existing `scripts/enrich-findings.mts`) | Maps this run's real SAST/symbolic findings to MITRE ATT&CK technique IDs, CIS Controls v8, and ISO/IEC 27001:2022 controls | **STRONG** | `enrich-findings.mts` already existed and was correct (`verify-enrichment.mts` passing) but had never been called outside its own test. Confirmed live: 14→28 findings mapped across two runs, differentiated mappings confirmed (not a bug always returning the fallback) — `reentrancy-eth`→T1565.002/Impact, `tx-origin`→T1078.004/Privilege Escalation, generic checks→T1190/Initial Access baseline. Rendered in `reports/latest.html`'s "Governance Framework Mapping" section (confirmed via direct grep both runs) |
| STRIDE coverage scorecard (`config/stride-coverage-map.json` + `scripts/verify-stride-coverage.mts`, both new) | Self-verifying scorecard: re-checks that 12 real file:line evidence references (2 per STRIDE category) still exist and are current; drift-detects new/changed files under `src/`,`scripts/`,`contracts/` not yet reviewed into the map | **STRONG** | All 6 categories have real, wired evidence (none forced) — e.g. Spoofing: `src/compliance/address_screener.py:145` (OFAC screening) + `contracts/solidity/VulnerableVault.sol:146` (tx-origin, SWC-115); Tampering: `scripts/run-sast-symbolic.py:254` (reentrancy-eth) + the Echidna harness's genuinely-falsified counterexample. Confirmed live: `6/6 categories covered, 0 stale entries`. Staleness test (corrupted line number) and missing-map test (deleted file) both confirmed fail-loud/non-blocking. `docs/STRIDE-CROSSWALK.md` auto-regenerates from the same JSON every run, confirmed same-instant timestamp as the HTML |
| 5-factor DREAD scoring (`scripts/run-dread-scoring.mts`, new, calls the pre-existing `computeDreadScore()` in `scripts/normalize-reports.mts`) | Real 5-factor DREAD vector (Damage/Reproducibility/Exploitability/Affected Users/Discoverability) per SAST/symbolic finding, with tool-specific calibration (Slither/Mythril bump exploitability) | **STRONG** | `computeDreadScore()` already existed and was correct (`verify-normalization.mts` passing) but, like `enrich-findings.mts`, had never been called outside its own test. Confirmed live: 28 findings scored this run, e.g. `weak-prng` (HIGH) → damage 8, reproducibility 7.5, exploitability 7.5 (bumped from base 7.0 by the Slither-tool calibration), affected 7.5, discoverability 7, composite 7.5. Deliberately NOT reconciled with the separate, simpler severity-lookup DREAD proxy that already feeds Grafana (`run-all-e2e.sh`'s `IMPACT_DREAD` → `ship-siem-telemetry.py`'s `blockchain_soc_dread_score` gauge) — the two numbers genuinely diverge per severity (e.g. HIGH: 8.0 flat vs. 7.4 vector-average) and reconciling them would mean touching already-live production code, out of scope for this additive work. Both are now documented side by side in the HTML section's own text so nothing is hidden |

## Zone 7 — Wallet/key/signing

| Component | Verdict | Why |
|---|---|---|
| Presign simulator, Vault Transit signing | STRONG | Confirmed live both runs |
| HSM signer (SoftHSM2) | PARTIAL | Software-emulated, no physical HSM; real PKCS#11 round-trip confirmed live both runs |
| Quorum signer (Shamir → MPC) | PARTIAL | Real 2-of-3 threshold + MPC "stand-in" layer, confirmed live both runs |

## Downstream: dashboards, notifications, CI/CD

| Component | Verdict | Why |
|---|---|---|
| DefectDojo ingestion | STRONG | Both `etherscan-lookup` and `indexer` builders confirmed landing live via DefectDojo's own API (3,934 total findings after both final runs); `flashloan-detector`/`rugpull-detector` correctly show "clean" for SecureVault |
| HTML report | STRONG | `#etherscan`/`#indexer` sections confirmed populated (not empty-state) on both final runs |
| Elasticsearch | STRONG | `blockchain-soc-events` (3,433 docs), `blockchain-soc-audit-logs` (152), new dedicated `blockchain-soc-onchain-events` (54 docs, indexer-only) |
| Kibana | STRONG | `soc-sections-a-c-events` category allowlist updated live to include `etherscan-lookup`, confirmed via saved-objects API |
| Grafana/Prometheus | STRONG | New real `timeseries` panel for indexer document counts, confirmed live via Grafana's own dashboard API (version bumped, 29 panels) and Prometheus's query API |
| Gmail notification | PARTIAL (real bug, unfixed) | `pipeline-all`'s own recipe (which contains the notify call) never runs when `pipeline-e2e` exits non-zero (health FAILED), because it's a `make` prerequisite, not called from inside the recipe. Confirmed firing correctly on both final runs (health OK both times) |
| GitOps / ArgoCD sync | STRONG | Confirmed correctly skipped on every HALT run this week, including both final Part C runs |
| Jenkins / GitLab CI | STRONG | Jenkins job `blockchain-soc-audit` genuinely runs `make pipeline-e2e` (74+ real build records, latest SUCCESS) |

---

## Deliberately not integrated (don't suggest re-adding without reading this)

- **Securify** — not present anywhere in the repo. Slither + Mythril already cover the same static/symbolic ground.
- **Brownie** — not present. Foundry + Hardhat already cover compile/test/deploy needs.
- **GitHub Actions** — no `.github/workflows` directory exists. CI/CD already runs through GitLab CI + Jenkins (both genuinely wired, confirmed live).
- **TensorFlow / graph neural networks** — deliberately rejected for the ML triage classifier. The only human-labeled smart-contract vulnerability dataset available (SmartBugs-curated) has just 143 contracts — far too few to train a graph model that generalizes; the larger Slither-labeled dataset would be a circular re-derivation of a tool already in this pipeline.

## Known, still-open issues

- Secret rotation (DefectDojo token, old Langfuse admin key, Slack webhook in `.env`) — explicitly deferred, requires the user's own dashboard access.
- Mythril wall-clock timeout flake — pre-existing, intermittent, not blocking.
- ~~Top-level verdict can't differentiate HALT reason by contract~~ — **fixed 2026-10-31**, see the "Per-contract security verdict" row in Zone 2/3's table above. The EXISTING overall gate still HALTs both targets the same way as before (that behavior was deliberately left untouched — SecureVault still can't legitimately GitOps-promote on this host until `trivy`/`sca`'s project-wide findings are separately addressed); what's new is a second, honest, additive signal that correctly distinguishes "this contract itself is clean" (SecureVault) from "this contract itself has real findings" (VulnerableVault), shown alongside — not instead of — the overall gate.
- The Makefile `notify-gmail` bug (see table above) — flagged only, not fixed.
- `scripts/run-formal-tools.cjs` (real instrumented-assert Mythril runs) remains disconnected from the live pipeline — only its smoke test (`verify-formal-tools.mts`, deliberately reports everything "blocked") runs in CI. Unchanged by this session's work.
- ~~`src/compliance/zk_attestation.py` remains disconnected from the live pipeline~~ — **fixed 2026-10-31**, see Zone 3 table above. The separate MCP tool (`compliance_mcp.py`) path is unchanged and still exists independently.
- ~~MITRE ATT&CK / CIS Controls v8 / ISO 27001 mappings (`enrich-findings.mts`), STRIDE threat-model coverage, and real 5-factor DREAD scoring (`computeDreadScore()`) were all real code but never wired into the live pipeline~~ — **fixed 2026-11-05**, see the new Zone 9 table above. These three were identified in a dedicated 8-framework audit earlier the same day (which also covered OWASP, MITRE, OSINT, CIS, ISO 27001, and Metasploit — OWASP/OSINT were already STRONG and wired, Metasploit remains genuinely ABSENT with no exploit-framework integration anywhere in the repo, neither of which needed fixing). This file was not updated to record that audit's findings as open issues before today; they are recorded here only now that they're closed, for an honest paper trail.
