# Blockchain Security SOC — Implementation Checklist V10.3

**Project:** Autonomous AI-Native Blockchain Security Operations Center (SOC) — Enterprise V10.3  
**Prepared for:** Saleem Ali  
**Primary execution environment:** Kali Linux VM on Windows 11 host  
**AI inference host:** Windows GPU host via mTLS-protected Ollama bridge  
**Source of truth:** Private GitLab repository, Git history, CI/CD artifacts, and this checklist  
**Companion documents:** `docs/HANDOFF.md`, `docs/DECISIONS.md` (optional), `docs/VALIDATION/` (optional)  
**Blueprint/checklist source:** Enterprise V10.3 blueprint and implementation checklist supplied with this project

---

## Operating rules

1. Work in the listed order. Do **not** begin a later phase until the current phase gate is verified.
2. Use a focused Perplexity thread for one bounded task or tightly related task group—not one giant project chat.
3. A task is `✅ Complete` only after implementation, relevant validation, evidence, and a Git commit exist.
4. Use the actual Kali Linux repository, test output, Git history, and GitLab CI output as the source of truth. Do not mark an item complete based only on an AI suggestion.
5. Keep secrets out of Git and chat: `.env`, PATs, private keys, mTLS private keys, HSM/MPC material, Shamir shares, production wallet keys, raw forensic evidence, and unredacted SAR data.
6. Use `🟨 Stubbed` for interfaces intentionally created ahead of a later dependency. Record the dependency in the notes.
7. Use `🔒 Coursework simulation` whenever local containers, fixtures, testnets, emulators, mock external services, or simplified cryptography replace a production service.
8. Zone 9 reports must contain summary/redacted data only—never sealed evidence, raw key material, key shares, or unredacted compliance reports.

### Status legend

| Symbol | Meaning |
|---|---|
| ⬜ | Not started |
| 🟦 | In progress |
| 🟨 | Stubbed / waiting on a planned dependency |
| 🟪 | Blocked |
| 🟧 | Implemented but needs verification |
| ✅ | Complete and verified |
| 🔒 | Coursework simulation / documented scope reduction |

### Completion evidence rule

For every `✅ Complete` item, record:

- **Files changed**
- **Validation command(s)** and factual result
- **Evidence path** or GitLab CI job/artifact reference
- **Git commit hash**
- **Notes**, including constraints, future work, simulations, or dependencies

---

## Project state

| Field | Current value |
|---|---|
| Current phase | Phase 0 — Environment and prerequisites |
| Current task | P00-001 |
| Current branch | `main` |
| Last verified commit | Not yet created |
| Last updated | 2026-09-27 |
| Project workspace | Autonomous AI-Native Blockchain SOC — Enterprise V10.3 |

---

## Phase dashboard

| Phase | Name | Status | Phase gate evidence | Commit / tag |
|---:|---|---|---|---|
| 0 | Environment and prerequisites | ⬜ | — | — |
| 1 | Skeleton scaffold | ⬜ | — | — |
| 2 | Zone 1 — Ingestion Gateway | ⬜ | — | — |
| 3 | Zone 2 — DevSecOps Shield and Sanitization Gateway | ⬜ | — | — |
| 4 | Zone 3 — Compilation, Storage and MCP Middleware | ⬜ | — | — |
| 5 | Transport Bridge, Inference Layer, and Agent Swarm A–G | ⬜ | — | — |
| 6 | AVS Cryptographic Consensus | ⬜ | — | — |
| 7 | Deploy / Abort logic | ⬜ | — | — |
| 8 | Observability Network and RASP Shield | ⬜ | — | — |
| 9 | Zone 4 — Mitigation, Proposal Layer, and Egress Gateway | ⬜ | — | — |
| 10 | Zone 5 — Digital Forensics and Evidence Integrity | ⬜ | — | — |
| 11 | Zone 6 — Consensus Attack Detection and Prevention | ⬜ | — | — |
| 12 | Zone 7 — Wallet and Key Management Security | ⬜ | — | — |
| 13 | Zone 8 — Compliance and Regulatory Automation | ⬜ | — | — |
| 14 | Zone 9 — Unified Executive HTML Report Layer | ⬜ | — | — |
| 15 | Benchmarks, Dashboard, Documentation, and Outreach | ⬜ | — | — |

---

# Phase 0 — Environment and prerequisites

**Goal:** Prepare the Kali VM and Windows GPU host for secure, verified communication before project code is written.

| ID | Task | Status | Evidence / commit |
|---|---|---|---|
| P00-001 | Update the Kali Linux VM. | 🟧 | Host update and baseline checks passed on 2026-09-28; documentation/Git synchronization pending. |
| P00-002 | Install and verify Git, Node.js/npm, Python 3.11+, pip, Docker, and Docker Compose on Kali. | ⬜ | — |
| P00-003 | Install and verify Foundry (`forge`, `anvil`, `cast`) and Hardhat. | ⬜ | — |
| P00-004 | Install and verify Slither, Mythril, and Certora CLI, or document the Certora API-key alternative. | ⬜ | — |
| P00-005 | Install Ollama on Windows and pull the agreed local model set; record actual model names and versions. | ⬜ | — |
| P00-006 | Bind Ollama to loopback/non-default local port and configure a reverse proxy on the private interface at port 11434. | ⬜ | — |
| P00-007 | Generate private CA, server certificate, and client certificate for Kali-to-Windows mTLS. | ⬜ | — |
| P00-008 | Require a bearer token at the reverse proxy and ensure Ollama itself is not directly exposed on the LAN. | ⬜ | — |
| P00-009 | Verify Kali can make an authenticated mTLS request to the Windows Ollama proxy. | ⬜ | — |
| P00-010 | Create the private GitLab project / remote; define GitLab CI/CD as the implementation source of truth. | ⬜ | — |
| P00-011 | Prepare the GitHub account/public-mirror policy; do not configure automatic public mirroring. | ⬜ | — |
| P00-012 | Install DFIR tooling: Sleuth Kit, optional Autopsy GUI, Volatility 3, Plaso, dc3dd, libewf-tools, YARA, tshark/tcpdump, optional Zeek, and GPG or minisign. | ⬜ | — |
| P00-013 | Select and test a memory-acquisition method on a throwaway VM: VirtualBox core dump, LiME, or AVML. | ⬜ | — |
| P00-014 | Prepare a dedicated evidence-vault directory/volume with separate service-account ownership; optionally document MinIO Object Lock. | ⬜ | — |
| P00-015 | Create an operator signing key for evidence-manifest signing; keep private material outside Git. | ⬜ | — |

## P00 — evidence log

### P00-001 — Kali update

- **Status:** 🟧 Implemented but needs verification
- **Scope completed:** Kali package-index refresh, full-upgrade verification, broken-package repair check, package audit, held-package check, reboot-required check, and OS/kernel baseline capture.
- **Scope not completed:** Documentation commit, GitLab post/push, GitLab CI verification, GitHub post/push, and local/GitLab/GitHub three-way SHA synchronization.
- **Files changed:** `docs/CHECKLIST.md`, `docs/HANDOFF.md` — documentation update pending local commit.
- **Validation commands:**
  ```bash
  sudo apt update
  sudo apt full-upgrade -y
  sudo apt --fix-broken install -y
  dpkg --audit
  apt-mark showhold
  test -f /var/run/reboot-required && cat /var/run/reboot-required || true
  uname -a
  cat /etc/os-release
  git status
  git log -1 --oneline
  ```
- **Factual results:**
  - `sudo apt update` completed successfully; Kali Rolling, Docker Debian Bookworm, and GitHub CLI repositories refreshed; APT reported `All packages are up to date.`
  - `sudo apt full-upgrade -y` completed successfully: `Upgrading: 0, Installing: 0, Removing: 0, Not Upgrading: 0`.
  - `sudo apt --fix-broken install -y` completed without repair changes or errors.
  - `dpkg --audit` produced no output.
  - `apt-mark showhold` produced no output.
  - Reboot check result: `REBOOT_REQUIRED=no`.
  - OS baseline: Kali GNU/Linux Rolling `2026.3` (`kali-rolling`).
  - Kernel baseline: `7.1.5+kali-amd64`, Kali `7.1.5-1kali1`, dated `2026-07-29`.
  - Git status before documentation changes: branch `main`, up to date with `gitlab/main`, working tree clean.
  - Git HEAD/history diagnosis: `main`, `gitlab/main`, and `origin/main` were verified at pre-documentation commit `dc21e949e7e5e2088eb11f92dac77a998ffeecca`.
  - APT reported unused auto-installed packages; `sudo apt autoremove` was intentionally not run because removal is outside P00-001 scope.
- **Evidence path / CI job:** Sanitized Kali terminal evidence in the P00-001 implementation thread. No task-specific CI job applies to OS package maintenance; the later documentation-commit pipeline remains unverified.
- **Git commit:** Pending.
- **GitLab post / CI:** Pending.
- **GitHub post:** Pending.
- **Synchronization:** Pending; local `main`, `gitlab/main`, and `origin/main` have not yet been proven to resolve to the same SHA.
- **Security checks:** No secrets, tokens, private keys, raw evidence, or unredacted compliance data were recorded. No unrelated tooling was installed and no packages were removed.
- **Dependencies / limitations:** Git HEAD/history output must be diagnosed before the documentation commit. No coursework simulation applies to this host-maintenance task.
- **Next recommended task:** Finish P00-001 documentation review, commit locally, post to GitLab, wait for factual GitLab CI evidence, post the same commit to GitHub, and verify three-way SHA synchronization.

### P00-002 to P00-015 — evidence entries

> Copy the same evidence fields for each completed task. Keep secret values, private keys, bearer tokens, and internal addresses out of this document.

- **Task ID:**
- **Status:**
- **Files changed:**
- **Validation commands:**
- **Result:**
- **Evidence path / CI job:**
- **Commit:**
- **Notes / simulation / limitation:**

## P00-GATE — Phase 0 completion gate

- [ ] `forge --version` succeeds.
- [ ] `slither --version` succeeds.
- [ ] `vol --help` succeeds.
- [ ] `fls -V` succeeds.
- [ ] An authenticated mTLS `curl` from Kali reaches the Windows Ollama proxy.
- [ ] All Phase 0 task evidence is recorded above.
- [ ] A Phase 0 Git commit exists.
- [ ] `docs/HANDOFF.md` is updated for Phase 1.

**Gate status:** ⬜ Not ready  
**Verified by:**  
**Verification date:**  
**Gate commit/tag:**  

---

# Phase 1 — Skeleton scaffold

**Goal:** Establish the complete folder/file skeleton, forensic stubs, dependencies, and green placeholder pipeline. No unrecorded structural decisions after this phase.

| ID | Task | Status | Evidence / commit |
|---|---|---|---|
| P01-001 | Unpack/create the project skeleton in the Kali VM project directory. | ⬜ | — |
| P01-002 | Initialize Git and commit the full skeleton with every TODO stub. | ⬜ | — |
| P01-003 | Confirm required base layout: `contracts/`, `move/`, `test/`, `scripts/`, `src/`, `config/`, `dashboard/`, `docs/`, `.gitlab/`. | ⬜ | — |
| P01-004 | Add `src/forensics/`, `test/forensics/`, `config/opa/`, `src/mcp_middleware/forensic_tools.py`, and `docs/forensic-report-template.md`. | ⬜ | — |
| P01-005 | Add `# TODO(phase-10)` to each newly created forensic file. | ⬜ | — |
| P01-006 | Start the skeleton Docker Compose stack and verify the Redis stub starts cleanly. | ⬜ | — |
| P01-007 | Run `npm install` and `pip install -r requirements.txt` without errors. | ⬜ | — |
| P01-008 | Push to private GitLab and verify the placeholder `.gitlab-ci.yml` pipeline is green. | ⬜ | — |
| P01-009 | Read and map every `TODO(phase-N)` marker to the relevant future phase. | ⬜ | — |

## P01-GATE — Phase 1 completion gate

- [ ] Skeleton pipeline is green in GitLab.
- [ ] Repository tree matches the expected base and forensic layout.
- [ ] All TODO markers are accounted for.
- [ ] Baseline skeleton commit/tag exists.
- [ ] `docs/HANDOFF.md` is updated for Phase 2.

**Gate status:** ⬜ Not ready  
**Gate commit/tag:**  

---

# Phase 2 — Zone 1: Manifest-driven ingestion gateway

**Goal:** Validate target-project topology, dependency/toolchain hashes, and verified repository asset paths.

| ID | Task | Status | Evidence / commit |
|---|---|---|---|
| P02-001 | Configure sample `foundry.toml`, `hardhat.config.js`, and `Move.toml` values. | ⬜ | — |
| P02-002 | Add a deliberately flawed sample contract under `contracts/solidity/`. | ⬜ | — |
| P02-003 | Implement `scripts/ingest-manifests.mts` schema parsing and validation for Foundry, Hardhat, and Move manifests. | ⬜ | — |
| P02-004 | Implement dependency and compiler-toolchain hash verification. | ⬜ | — |
| P02-005 | Emit verified repository asset-map JSON for contracts, Move modules/packages, and test layouts. | ⬜ | — |
| P02-006 | Add the ingestion job to `.gitlab-ci.yml`. | ⬜ | — |
| P02-007 | Replace the Hardhat placeholder with an ingestion smoke test. | ⬜ | — |
| P02-008 | Verify Developer Push, webhook, and on-chain-event stub all reach the pipeline entry. | ⬜ | — |

## P02-GATE — Phase 2 completion gate

- [ ] A push runs the ingestion job.
- [ ] Tampering with a dependency hash fails the ingestion job.
- [ ] Verified asset-map JSON is produced.
- [ ] Handoff updated for Phase 3.

**Gate status:** ⬜ Not ready  
**Gate commit/tag:**  

---

# Phase 3 — Zone 2: DevSecOps shield and sanitization gateway

**Goal:** Perform static, symbolic, dependency, dynamic, and governance analysis while preventing untrusted source text from reaching the LLM layer unsanitized.

| ID | Task | Status | Evidence / commit |
|---|---|---|---|
| P03-001 | Wire Slither, Mythril, and Certora/alternative formal verification against the sample contract. | ⬜ | — |
| P03-002 | Implement `scripts/run-sca.sh` for dependency resolution and vulnerability lookup. | ⬜ | — |
| P03-003 | Add IAST wrappers that log EVM state transitions during tests. | ⬜ | — |
| P03-004 | Implement `scripts/ast-mask.mts` for AST parsing, string-literal hashing, and maximum-depth routing to manual review. | ⬜ | — |
| P03-005 | Add a prompt-injection contract fixture and verify masking returns hash/tag representation only. | ⬜ | — |
| P03-006 | Implement protected-branch production-readiness gate; fail closed if hardware-cluster check fails. | ⬜ | — |
| P03-007 | Run Zone 2 inside an isolated Docker/GitLab Runner environment: no privileged mode and no host mounts. | ⬜ | — |
| P03-008 | Add CSET/CISA or an approved open-source CMMC/NIST governance scanner. | ⬜ | — |
| P03-009 | Add real Foundry `Exploit.t.sol` and `Invariants.t.sol` examples and validate the exploit fixture. | ⬜ | — |
| P03-010 | Create `src/agents/upgrade5_defi_attacks.py` front-running detector interface/tests as a safe stub pending Phase 11 mempool data. | ⬜ | — |
| P03-011 | Implement rug-pull signatures: unrestricted mint, untimelocked LP, unsafe ownership, and hidden post-launch fee controls. | ⬜ | — |
| P03-012 | Implement flash-loan invariant generation and Anvil-fork validation for oracle/pool-drain conditions. | ⬜ | — |

## P03-GATE — Phase 3 completion gate

- [ ] Protected production branch is blocked when the cluster check is offline.
- [ ] AST masking neutralizes the prompt-injection fixture.
- [ ] Zone 2 tests and isolated runner validation pass.
- [ ] Phase 11 forward dependency for mempool monitoring is documented.

**Gate status:** ⬜ Not ready  
**Gate commit/tag:**  

---

# Phase 4 — Zone 3: Compilation, storage, and MCP middleware

**Goal:** Persist sanitized findings, score/enrich them, construct attack paths, and expose safe read-oriented tools through an MCP middleware container.

| ID | Task | Status | Evidence / commit |
|---|---|---|---|
| P04-001 | Implement SQLite broker storage with WAL mode, exclusive locking, optional Redis cache, and pre-swarm snapshots. | ⬜ | — |
| P04-002 | Implement `scripts/normalize-reports.mts` DREAD scoring. | ⬜ | — |
| P04-003 | Implement `scripts/enrich-findings.mts` mappings for ATT&CK, CIS, ISO 27001, and CSET. | ⬜ | — |
| P04-004 | Implement attack-path graph, `list_attack_paths()`, and `plan_remediation()`. | ⬜ | — |
| P04-005 | Scaffold the benchmark-suite interface against sample contracts. | ⬜ | — |
| P04-006 | Implement Anvil-fork MCP sandbox with controlled `forge test` execution. | ⬜ | — |
| P04-007 | Implement read-only Sleuth Kit host-forensics MCP wrapper with structured JSON output. | ⬜ | — |
| P04-008 | Create telemetry MCP stubs for Prometheus, ELK, Web3.py RPC, and GraphSense; defer live integration to Phase 8. | ⬜ | — |
| P04-009 | Deploy MCP middleware pool in Docker Compose. | ⬜ | — |
| P04-010 | Enforce storage read-only behavior for agent roles. | ⬜ | — |

## P04-GATE — Phase 4 completion gate

- [ ] MCP client calls attack-path listing.
- [ ] MCP client runs controlled Anvil sandbox operation.
- [ ] MCP client lists a disk image’s partitions through host-forensics wrapper.
- [ ] Direct storage write from agent role fails.

**Gate status:** ⬜ Not ready  
**Gate commit/tag:**  

---

# Phase 5 — Transport bridge, inference layer, and Agent Swarm A–G

**Goal:** Securely call local models on the Windows GPU host with sequential, VRAM-aware agent orchestration.

| ID | Task | Status | Evidence / commit |
|---|---|---|---|
| P05-001 | Implement mTLS/bearer-aware `src/llm_client/ollama_client.py`, per-agent context sizes, `purge_model()`, and `agent_stage()` wrapper. | ⬜ | — |
| P05-002 | Apply safe shell configuration variables on Kali; do not commit secrets. | ⬜ | — |
| P05-003 | Validate raw authenticated chat call end-to-end before agent wiring. | ⬜ | — |
| P05-004 | Verify model lifecycle: load, call, purge, then confirm host model list is empty. | ⬜ | — |
| P05-005 | Document practical Tier 1/Tier 2 model schedule for the available VRAM. | ⬜ | — |
| P05-006 | Implement Agent A: smart-contract auditor. | ⬜ | — |
| P05-007 | Implement Agent B: SIEM threat hunter. | ⬜ | — |
| P05-008 | Implement Agent C: compliance judge. | ⬜ | — |
| P05-009 | Implement Agent D: offensive red teamer, restricted to authorized fixtures/forks. | ⬜ | — |
| P05-010 | Implement Agent E: incident commander. | ⬜ | — |
| P05-011 | Implement Agent F: deep logic / forensic and benchmark hooks. | ⬜ | — |
| P05-012 | Implement Agent G: guardrail watchdog, OPA/JWT/mTLS checks, 300-second limit. | ⬜ | — |
| P05-013 | Implement sequential LangGraph wiring and escalation/fallback model for disputed findings. | ⬜ | — |
| P05-014 | Run a full Zone 1→2→3→swarm sample pass with verified model unload between every stage. | ⬜ | — |

## P05-GATE — Phase 5 completion gate

- [ ] One full pass completes without out-of-memory failure on the target hardware.
- [ ] Model process/list is empty between stages after purge.
- [ ] All agents respect typed interfaces and least-privilege tool boundaries.

**Gate status:** ⬜ Not ready  
**Gate commit/tag:**  

---

# Phase 6 — AVS cryptographic consensus

**Goal:** Independently reproduce findings before a result is trusted to change deployment behavior.

| ID | Task | Status | Evidence / commit |
|---|---|---|---|
| P06-001 | Implement `src/consensus/avs_gate.py` and finding-attestation interface. | ⬜ | — |
| P06-002 | Stand up three local validator containers; document this as a coursework simulation. | ⬜ | — |
| P06-003 | Re-execute each PoC in isolated Anvil environments. | ⬜ | — |
| P06-004 | Implement a greater-than-66.7% supermajority rule. | ⬜ | — |
| P06-005 | Implement threshold BLS or a documented multisignature-hash-agreement stand-in. | ⬜ | — |
| P06-006 | Verify hallucinated/non-reproducible findings are rejected and do not block the pipeline. | ⬜ | — |
| P06-007 | Test confirmed-exploit and deliberate-false-finding paths. | ⬜ | — |
| P06-008 | Emit a versioned `case-opened` event for Phase 10 forensic consumption. | ⬜ | — |

## P06-GATE — Phase 6 completion gate

- [ ] Real confirmed exploit produces signed/attested result.
- [ ] Fake exploit is rejected.
- [ ] Case-opened event is present and schema is recorded.

**Gate status:** ⬜ Not ready  
**Gate commit/tag:**  

---

# Phase 7 — Deploy / abort logic

**Goal:** Make consensus outcomes safely affect pipeline behavior, with local/test-only deployment mechanisms until production controls exist.

| ID | Task | Status | Evidence / commit |
|---|---|---|---|
| P07-001 | Implement consensus-confirmed deploy path using kind/minikube or documented Docker Compose simulation. | ⬜ | — |
| P07-002 | Add Vault dev-mode or documented safe coursework secret-store integration for deploy. | ⬜ | — |
| P07-003 | Implement consensus-rejected abort path and readiness-policy failure. | ⬜ | — |
| P07-004 | Generate any swarm patch only inside an offline/sandboxed container. | ⬜ | — |
| P07-005 | Create draft GitLab Merge Request workflow with tracking labels and finding references. | ⬜ | — |
| P07-006 | Snapshot job logs, WAL, AST, PoC, and relevant artifacts into protected staging for Phase 10 sealing. | ⬜ | — |
| P07-007 | Test deploy and abort branches end-to-end on authorized sample contracts. | ⬜ | — |

## P07-GATE — Phase 7 completion gate

- [ ] Deploy and abort paths are both proven.
- [ ] Protected staging snapshot exists in both paths.
- [ ] Any deployment mechanism is clearly marked as production-capable or coursework simulation.

**Gate status:** ⬜ Not ready  
**Gate commit/tag:**  

---

# Phase 8 — Observability network and RASP shield

**Goal:** Monitor runtime/on-chain signals, verify suspicious activity through safe forks, and feed validated telemetry to the response path.

| ID | Task | Status | Evidence / commit |
|---|---|---|---|
| P08-001 | Deploy Prometheus plus ELK, or document Grafana/Loki lightweight replacement. | ⬜ | — |
| P08-002 | Implement real Prometheus and ELK telemetry query functions. | ⬜ | — |
| P08-003 | Implement RASP shield: read-only RPC traces, GraphSense integration/adapter, and optional Forta/Rekt signals. | ⬜ | — |
| P08-004 | Wire Agent E shadow-fork transaction verification and persistent network logs. | ⬜ | — |
| P08-005 | Route validated RASP findings to Agent B. | ⬜ | — |
| P08-006 | Confirm deploy and abort branches emit continuous telemetry. | ⬜ | — |
| P08-007 | Emit fast-path mitigation signal payload to Phase 9. | ⬜ | — |

## P08-GATE — Phase 8 completion gate

- [ ] A simulated suspicious authorized fork transaction produces an alert.
- [ ] Alert reaches Agent B and Phase 9 signal interface.

**Gate status:** ⬜ Not ready  
**Gate commit/tag:**  

---

# Phase 9 — Zone 4: Mitigation, proposal layer, and egress gateway

**Goal:** Ensure sensitive actions remain human-authorized, policy-checked, and protected by quarantine/release controls.

| ID | Task | Status | Evidence / commit |
|---|---|---|---|
| P09-001 | Implement `scripts/incident-orchestrator.mts` with test-safe multi-sig proposal, GitLab issue, network-policy simulation, and non-sensitive telemetry output. | ⬜ | — |
| P09-002 | Implement `config/opa/agent_policy.rego` least-privilege rules for agent and `soc-operator` roles. | ⬜ | — |
| P09-003 | Implement MCP OPA guardrail; enforce policy evaluation for every agent tool call. | ⬜ | — |
| P09-004 | Implement encrypted GitLab Quarantine staging workflow and signed-human-release-token verification. | ⬜ | — |
| P09-005 | Implement GitHub mirror trigger only after explicit valid human release; no automatic public mirror. | ⬜ | — |
| P09-006 | Test agent denial for remediation write/live isolation and operator allowance for authorized action. | ⬜ | — |
| P09-007 | Test invalid/unsigned release token blocks public mirror. | ⬜ | — |
| P09-008 | Prove no direct outbound mirroring path exists. | ⬜ | — |

## P09-GATE — Phase 9 completion gate

- [ ] Agent-denial policy test passes.
- [ ] Invalid release-token denial test passes.
- [ ] Direct-outbound-mirror absence test passes.

**Gate status:** ⬜ Not ready  
**Gate commit/tag:**  

---

# Phase 10 — Zone 5: Digital forensics and evidence integrity

**Goal:** Add integrity-preserving, human-authorized DFIR workflows. Originals remain immutable; agents receive only verified, sanitized working copies.

## Phase 10a — Integrity core

| ID | Task | Status | Evidence / commit |
|---|---|---|---|
| P10A-001 | Implement streaming SHA-256 and SHA-512, manifest Merkle root, signing, and verification. | ⬜ | — |
| P10A-002 | Implement `forensics.db`, evidence/custody tables, append-only triggers, entry hash chain, and chain verification. | ⬜ | — |
| P10A-003 | Implement write-once evidence vault: `seal()`, `verify()`, and re-hashing `open_working_copy()`. | ⬜ | — |
| P10A-004 | Test sealed-file alteration detection, custody-row alteration detection, and UPDATE/DELETE rejection. | ⬜ | — |

## Phase 10b — Policy and safety

| ID | Task | Status | Evidence / commit |
|---|---|---|---|
| P10B-001 | Implement forensic OPA policy: agents read derived artifacts only; `soc-operator` acquires; no one alters originals. | ⬜ | — |
| P10B-002 | Implement deterministic evidence sanitizer: structured parsing, free-text hash/length masking, size caps, data-only framing. | ⬜ | — |
| P10B-003 | Test prompt-injection text is sanitized before any agent receives it. | ⬜ | — |
| P10B-004 | Make Agent G block writes to sealed evidence paths. | ⬜ | — |

## Phase 10c — Acquisition in volatility order

| ID | Task | Status | Evidence / commit |
|---|---|---|---|
| P10C-001 | Implement authorized memory, network, disk, log, and pipeline-state acquisition in RFC 3227 order. | ⬜ | — |
| P10C-002 | Add container/Kubernetes collectors. | ⬜ | — |
| P10C-003 | Add pipeline-state collector: CI logs/artifacts, WAL, AST, PoC, CVL, AVS attestations. | ⬜ | — |
| P10C-004 | Add authorized on-chain collection: transactions, receipts, traces, state differences, pinned block range. | ⬜ | — |
| P10C-005 | Route every collector through sealing and custody logging with tool/version attribution. | ⬜ | — |
| P10C-006 | Enforce `soc-operator` acquisition authorization; agents may only produce acquisition plans. | ⬜ | — |

## Phase 10d — Analysis and MCP registration

| ID | Task | Status | Evidence / commit |
|---|---|---|---|
| P10D-001 | Implement structured Sleuth Kit disk-forensics wrapper. | ⬜ | — |
| P10D-002 | Implement structured Volatility 3 memory-forensics wrapper. | ⬜ | — |
| P10D-003 | Implement Plaso/mactime sorted forensic timeline with evidence IDs. | ⬜ | — |
| P10D-004 | Implement Anvil replay, state differences, address graph, and fund-flow queries for on-chain forensics. | ⬜ | — |
| P10D-005 | Register all forensic MCP tools and force every call through OPA. | ⬜ | — |
| P10D-006 | Update Agents A–F to use authorized forensic tools; retain exactly seven agents. | ⬜ | — |
| P10D-007 | Feed reconstructed attack paths into Zone 3 graph with ATT&CK mappings. | ⬜ | — |

## Phase 10e — Reporting and feedback

| ID | Task | Status | Evidence / commit |
|---|---|---|---|
| P10E-001 | Create 13-section forensic report template. | ⬜ | — |
| P10E-002 | Implement report generator using sealed evidence metadata, verified copies, timeline, graph, and custody export. | ⬜ | — |
| P10E-003 | Export STIX 2.1 IOCs and require analyst sign-off before final status. | ⬜ | — |
| P10E-004 | Send redacted release only through Phase 9 HITL egress path. | ⬜ | — |
| P10E-005 | Feed validated IOCs/addresses to Agent B and Zone 3 graph. | ⬜ | — |
| P10E-006 | Optionally attest manifest hash through validator quorum; label scope accurately. | ⬜ | — |

## Phase 10f — End-to-end drills

| ID | Task | Status | Evidence / commit |
|---|---|---|---|
| P10F-001 | Drill 1: throwaway-host compromise acquisition, sealing, analysis, timeline, and report. | ⬜ | — |
| P10F-002 | Drill 2: authorized historical exploit replay, fund tracing, and report. | ⬜ | — |
| P10F-003 | Drill 3: malicious contract fixture; verify masking, sealing, and report. | ⬜ | — |
| P10F-004 | Drill 4: tamper sealed evidence; verify detection, alert, and custody entry. | ⬜ | — |
| P10F-005 | Document every simulation/simplification: VirtualBox, local validators, no external timestamp authority, etc. | ⬜ | — |

## P10-GATE — Phase 10 completion gate

- [ ] All four drills produce a signed/analyst-approved report within the coursework environment.
- [ ] Drill 4 tampering is detected.
- [ ] Evidence originals are not modified by agents.
- [ ] Every forensic MCP call is OPA checked.

**Gate status:** ⬜ Not ready  
**Gate commit/tag:**  

---

# Phase 11 — Zone 6: Consensus attack detection and prevention

**Goal:** Add continuous network-layer consensus monitoring distinct from application/smart-contract auditing.

| ID | Task | Status | Evidence / commit |
|---|---|---|---|
| P11-001 | Implement P2P/indexer listener for propagation timing, peer topology, and mempool activity. | ⬜ | — |
| P11-002 | Implement reorganization monitor using chain finality-depth configuration. | ⬜ | — |
| P11-003 | Implement PoW/PoS concentration tracker with warning/critical thresholds. | ⬜ | — |
| P11-004 | Implement selfish-mining anomaly detector using observed versus expected orphan/stale rate. | ⬜ | — |
| P11-005 | Implement eclipse detector using peer diversity and clustering signals. | ⬜ | — |
| P11-006 | Register consensus-monitor MCP functions. | ⬜ | — |
| P11-007 | Enrich/tag Zone 6 findings in Zone 3 graph as consensus-layer findings. | ⬜ | — |
| P11-008 | Route actionable consensus findings through AVS before Phase 9 mitigation. | ⬜ | — |
| P11-009 | Implement consensus OPA policy: agents read/correlate; only operator may mitigate/override. | ⬜ | — |
| P11-010 | Update Agents B, E, and G to consume, trigger, rate-limit, and validate the tool correctly. | ⬜ | — |
| P11-011 | Drill concentration/selfish-mining scenario on an authorized local test environment. | ⬜ | — |
| P11-012 | Drill deep reorganization scenario on an authorized local test environment. | ⬜ | — |
| P11-013 | Connect Phase 3 front-running detector to the verified mempool feed. | ⬜ | — |

## P11-GATE — Phase 11 completion gate

- [ ] Both drills generate signed AVS-confirmed findings and Phase 9 notifications.
- [ ] Normal window produces no false alert in the test scenario.
- [ ] Phase 3 forward dependency is resolved or explicitly documented.

**Gate status:** ⬜ Not ready  
**Gate commit/tag:**  

---

# Phase 12 — Zone 7: Wallet and key management security

**Goal:** Protect operational keys through appropriate controls and validate third-party wallet contracts without exposing real secret material to agents.

| ID | Task | Status | Evidence / commit |
|---|---|---|---|
| P12-001 | Establish evidence-signing key protection through Shamir N-of-M procedure; document reconstruction procedure without storing shares. | ⬜ | — |
| P12-002 | Implement/wrap audited Shamir share creation/reconstruction integration. | ⬜ | — |
| P12-003 | Provision HSM or documented emulator for test-safe Gnosis Safe signer integration. | ⬜ | — |
| P12-004 | Implement HSM signing interface with no raw-key-export path. | ⬜ | — |
| P12-005 | Provision MPC/stand-in across at least two replicas for relayer key operations. | ⬜ | — |
| P12-006 | Implement joint-signature relayer interface and prove no replica retains complete key material. | ⬜ | — |
| P12-007 | Implement mandatory Anvil pre-sign simulation for relayer transactions. | ⬜ | — |
| P12-008 | Register wallet-audit MCP tool with wallet-specific Slither/Mythril/Certora rules. | ⬜ | — |
| P12-009 | Add deliberately vulnerable demo wallet contract. | ⬜ | — |
| P12-010 | Update Agents A, D, and E for wallet audit, authorized PoC synthesis, and pre-sign simulation. | ⬜ | — |
| P12-011 | Implement wallet OPA policy for agent and operator actions. | ⬜ | — |
| P12-012 | Test agent denial for Shamir reconstruction and HSM signing. | ⬜ | — |
| P12-013 | Drill signature-replay detection and authorized local PoC validation. | ⬜ | — |
| P12-014 | Drill wrong-recipient pre-sign simulation detection. | ⬜ | — |

## P12-GATE — Phase 12 completion gate

- [ ] Wallet vulnerability and pre-sign drills succeed.
- [ ] OPA denial test passes.
- [ ] No non-operator path can cause a real signature.

**Gate status:** ⬜ Not ready  
**Gate commit/tag:**  

---

# Phase 13 — Zone 8: Compliance and regulatory automation

**Goal:** Monitor and draft compliance artifacts without controlling transaction inclusion or autonomously filing external reports.

| ID | Task | Status | Evidence / commit |
|---|---|---|---|
| P13-001 | Implement continuous address screening using local/approved sanctions snapshot and risk-address data. | ⬜ | — |
| P13-002 | Implement AML-pattern rules and documented graph-model approach for structuring, layering, and mixer signals. | ⬜ | — |
| P13-003 | Implement documented simplified ZK attestation using an existing safe library/primitive. | ⬜ | — |
| P13-004 | Implement draft SAR/report generator. | ⬜ | — |
| P13-005 | Register compliance-screen MCP tool. | ⬜ | — |
| P13-006 | Add compliance-tagged findings to Zone 3 graph. | ⬜ | — |
| P13-007 | Implement compliance OPA policy with `compliance-officer` approval/filing role. | ⬜ | — |
| P13-008 | Update Agents B, C, and G for screening, framework mapping/drafting, and approval blocking. | ⬜ | — |
| P13-009 | Test agent denial for report approval and filing. | ⬜ | — |
| P13-010 | Drill screening of authorized public test-risk-address data and draft report generation. | ⬜ | — |
| P13-011 | Drill ZK attestation verification without disclosing underlying transaction list. | ⬜ | — |
| P13-012 | Confirm release uses Phase 9 HITL egress path only. | ⬜ | — |
| P13-013 | Document why this monitoring layer does not control blockchain transaction inclusion. | ⬜ | — |

## P13-GATE — Phase 13 completion gate

- [ ] Screening and ZK drills succeed in documented scope.
- [ ] OPA denial test passes.
- [ ] No external filing or on-chain transaction blocking path exists.

**Gate status:** ⬜ Not ready  
**Gate commit/tag:**  

---

# Phase 14 — Zone 9: Unified executive HTML report layer

**Goal:** Generate a single self-contained, sanitized executive report from verified outputs across Zones 1–8 and benchmarks.

## Phase 14a — Port existing report tool

| ID | Task | Status | Evidence / commit |
|---|---|---|---|
| P14A-001 | Port existing `generate-html-report.mts` features into this repository. | ⬜ | — |
| P14A-002 | Verify standalone rendering against synthetic sanitized sample JSON. | ⬜ | — |

## Phase 14b — Status aggregator

| ID | Task | Status | Evidence / commit |
|---|---|---|---|
| P14B-001 | Implement `scripts/aggregate-status.mts` reading allowed summary fields from Zones 3–8 and benchmark suite. | ⬜ | — |
| P14B-002 | Write versioned `status.json` matching the documented aggregation contract. | ⬜ | — |
| P14B-003 | Add tests proving `status.json` excludes raw private keys, shares, sealed evidence, and unredacted SARs. | ⬜ | — |

## Phase 14c — Extend report generator

| ID | Task | Status | Evidence / commit |
|---|---|---|---|
| P14C-001 | Add Zone 6 consensus panel and alert timeline. | ⬜ | — |
| P14C-002 | Add Zone 7 wallet audit/key-scheme coverage panel. | ⬜ | — |
| P14C-003 | Add Zone 5 forensic-case timeline with redacted summaries only. | ⬜ | — |
| P14C-004 | Add executive KPI cards. | ⬜ | — |
| P14C-005 | Add generated strengths, flaws, and recommended-action summaries using safe templates. | ⬜ | — |
| P14C-006 | Verify existing compliance register rendering against real sanitized Zone 8 shape. | ⬜ | — |

## Phase 14d — Generation cadence

| ID | Task | Status | Evidence / commit |
|---|---|---|---|
| P14D-001 | Add `npm run report` or `make status-report` outputting timestamped HTML. | ⬜ | — |
| P14D-002 | Add final GitLab CI report stage producing internal `reports/latest.html`. | ⬜ | — |
| P14D-003 | Add daily scheduled CI report generation for continuous Zones 6 and 8. | ⬜ | — |
| P14D-004 | Prove the report generator has no MCP registration and is not agent-callable. | ⬜ | — |

## Phase 14e — Safety and release

| ID | Task | Status | Evidence / commit |
|---|---|---|---|
| P14E-001 | Keep reports internal by default through `.gitignore` / mirror exclusion. | ⬜ | — |
| P14E-002 | Test redaction using fixture forensic/compliance data. | ⬜ | — |
| P14E-003 | Document external sharing only through Phase 9 HITL gateway. | ⬜ | — |
| P14E-004 | Verify standalone browser rendering of panels, KPI cards, tables, and charts. | ⬜ | — |

## P14-GATE — Phase 14 completion gate

- [ ] `npm run report` produces one self-contained HTML report.
- [ ] Report accurately reflects current sanitized status of Zones 1–8 and benchmark suite.
- [ ] No raw sensitive data appears in report fixtures or output.
- [ ] Browser opens the report without server setup.

**Gate status:** ⬜ Not ready  
**Gate commit/tag:**  

---

# Phase 15 — Benchmarks, dashboard, documentation, and outreach

**Goal:** Measure the completed system honestly and turn it into a demonstrable portfolio, paper, and presentation asset.

## Phase 15a — Empirical benchmarking

| ID | Task | Status | Evidence / commit |
|---|---|---|---|
| P15A-001 | Collect 50+ authorized historical exploit fixtures from DefiHackLabs/SolidiFI or approved alternatives. | ⬜ | — |
| P15A-002 | Run the full pipeline and record results through benchmark suite. | ⬜ | — |
| P15A-003 | Record precision, recall, autonomous PoC pass rate, MTTR, model versions, hardware, and failures. | ⬜ | — |
| P15A-004 | Compare honestly against targets: P > 92%, R > 88%, PoC > 80%, MTTR < 45 s. | ⬜ | — |
| P15A-005 | Add forensic metrics: integrity-verification pass rate, time-to-timeline, and IOC extraction accuracy. | ⬜ | — |

## Phase 15b — Dashboard / recruiter demo

| ID | Task | Status | Evidence / commit |
|---|---|---|---|
| P15B-001 | Build Next.js/React dashboard with non-sensitive pipeline, graph, and agent-stream views. | ⬜ | — |
| P15B-002 | Add redacted forensic-case timeline and evidence-integrity widget. | ⬜ | — |
| P15B-003 | Deploy only non-sensitive telemetry to Vercel or documented alternative. | ⬜ | — |
| P15B-004 | Implement documented one-command demo target. | ⬜ | — |
| P15B-005 | Ensure public repo contains passing CI, OPA policies, and pre-commit checks without secrets. | ⬜ | — |

## Phase 15c — Paper and scholarship material

| ID | Task | Status | Evidence / commit |
|---|---|---|---|
| P15C-001 | Draft IEEE/ACM-style paper with only supportable novelty claims. | ⬜ | — |
| P15C-002 | Insert measured benchmark table into statement-of-purpose material. | ⬜ | — |
| P15C-003 | Write privacy/data-sovereignty section with accurately scoped offline inference, mTLS, and compliance claims. | ⬜ | — |

## Phase 15d — Video and LinkedIn

| ID | Task | Status | Evidence / commit |
|---|---|---|---|
| P15D-001 | Record authorized 3–5 minute technical walkthrough. | ⬜ | — |
| P15D-002 | Record authorized 2–3 minute forensic integrity walkthrough. | ⬜ | — |
| P15D-003 | Prepare LinkedIn posts with accurate scope, results, and links. | ⬜ | — |
| P15D-004 | Link public GitHub repository, dashboard, and paper only after security review. | ⬜ | — |

## P15-GATE — Project completion gate

- [ ] Every phase gate is verified.
- [ ] Every task is either `✅ Complete` or explicitly documented as `🔒 Coursework simulation` with a limitation and validation.
- [ ] Benchmark results are measured and honestly reported.
- [ ] Public-facing artifacts contain no secrets, raw evidence, key material, or unredacted compliance material.
- [ ] Zone 9 executive report reflects the final sanitized project state.

**Final project status:** ⬜ Not complete  
**Final verification date:**  
**Final release commit/tag:**  

---

# Task-update template

Copy this block under a task or in the relevant phase evidence section when work is finished:

```markdown
### [TASK-ID] — [Task title]

- **Status:** 🟧 Needs verification / ✅ Complete / 🟨 Stubbed / 🟪 Blocked
- **Scope completed:**
- **Files changed:**
- **Validation commands:**
  ```bash
  # commands actually run
  ```
- **Factual results:**
- **Evidence path / CI job:**
- **Git commit:**
- **Security checks:**
- **Dependencies / forward references:**
- **Coursework simulation / limitations:**
- **Next recommended task:**
```

# Phase-completion template

Use this immediately before marking a phase complete:

```markdown
## Phase [N] completion record

- **Phase:**
- **Gate status:** ✅ Complete / 🟪 Blocked
- **Required Done-when criteria:**
  - [ ] Criterion 1
  - [ ] Criterion 2
- **Validated by:**
- **Date:**
- **Git commit/tag:**
- **GitLab pipeline / evidence:**
- **Known limitations / simulations:**
- **Handoff updated:** `docs/HANDOFF.md`
- **Approved next phase:**
```
