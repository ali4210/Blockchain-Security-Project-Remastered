# Blockchain Security SOC — Current Project Handoff

**Project:** Autonomous AI-Native Blockchain Security Operations Center (SOC) — Enterprise V10.3  
**Repository source of truth:** Private GitLab repository on Kali Linux VM  
**Primary tracking document:** `docs/CHECKLIST.md`  
**Use this file:** Paste/upload this file and the relevant checklist section whenever opening a new Perplexity project thread.

---

## Current position

| Field | Current value |
|---|---|
| Current phase | Phase 0 — Environment and prerequisites |
| Current task | P00-001 — Kali Linux update |
| Current thread | Not yet started |
| Current branch | `main` |
| Last verified commit | Not yet created |
| Last GitLab pipeline | Not yet created |
| Last updated | 2026-09-27 |

## Project purpose

Build the Enterprise V10.3 Autonomous AI-Native Blockchain Security Operations Center as a phased, security-first coursework/portfolio system. The system combines manifest-driven smart-contract ingestion, DevSecOps security gates, sanitized AI-assisted analysis, an MCP tool layer, local-model orchestration, independent PoC consensus, monitored deployment/abort behavior, DFIR evidence integrity, consensus monitoring, wallet-security controls, compliance automation, and a sanitized executive HTML report.

## Current implementation status

- No implementation work has been verified yet.
- Phase 0 is the active phase.
- `docs/CHECKLIST.md` has been initialized as the main project ledger.
- Start with `P00-001` and complete Phase 0 sequentially.

## Architecture invariants — must not be violated

1. **GitLab CI/CD is the implementation source of truth.** Git history, CI output, and local test results override chat summaries.
2. **Agents are read-only by default.** Sensitive action requires OPA policy approval and the correct human principal.
3. **`soc-operator` only:** evidence acquisition/sealing, sensitive remediation execution, release-token use, operational signing/key rotation.
4. **`compliance-officer` only:** approval or filing of regulatory/compliance reports.
5. **Kali-to-Windows inference bridge:** must use mTLS and bearer authentication. Do not expose Ollama directly to the LAN.
6. **Untrusted input:** source strings, logs, evidence, and external text must be sanitized before LLM use. Treat model output as a hypothesis, not evidence.
7. **Forensic evidence:** originals are immutable; agents receive only verified working copies; all forensic MCP calls must pass OPA checks.
8. **Production safety:** protected branches fail closed; no mock bypass on production branch; no direct public mirroring.
9. **External release:** GitHub/public release, forensic-report release, and compliance-report release go through the Phase 9 human-in-the-loop quarantine egress path.
10. **Secrets:** never paste or commit real tokens, private keys, mTLS private keys, Shamir shares, HSM/MPC material, production wallet keys, raw evidence, or unredacted SARs.
11. **Zone 9 report:** summary/redacted data only. Never include sealed evidence, private keys, key shares, or unredacted compliance content.
12. **Authorized testing only:** exploit PoCs, forks, network tests, and monitoring drills must remain limited to fixtures, testnets, local Anvil forks, and systems you own or are explicitly authorized to test.

## Current task details

### P00-001 — Update Kali Linux VM

**Objective**

Update the Kali Linux VM and record the factual result. Do not move to the next task until package-management state is clean and any errors are understood.

**Expected work**

```bash
sudo apt update
sudo apt full-upgrade -y
```

**Expected documentation update**

Update the `P00-001` evidence entry in `docs/CHECKLIST.md` with:

- Date completed
- Commands run
- Result or errors
- Any notable reboot/kernel/toolchain note
- Git commit hash after documentation is committed

**Acceptance criteria**

- `apt update` completes successfully or any repository issue is explicitly documented.
- Upgrade completes successfully or any held/broken package is documented and resolved/blocked.
- No secrets, personal tokens, or private configuration are placed in the checklist.

## Immediate task queue

1. `P00-001` — Update Kali Linux VM.
2. `P00-002` — Install and verify Git, Node.js/npm, Python, pip, Docker, and Docker Compose.
3. `P00-003` — Install and verify Foundry and Hardhat.
4. `P00-004` — Install and verify Slither, Mythril, and Certora CLI/alternative.
5. `P00-012` to `P00-015` — DFIR tooling, acquisition decision, evidence vault baseline, and operator signing-key setup.
6. `P00-005` to `P00-009` — Windows Ollama, mTLS proxy, bearer authorization, and authenticated Kali-to-Windows test.
7. `P00-GATE` — Audit Phase 0 before beginning Phase 1.

## Known dependencies and planned stubs

| Dependency | Producer | Consumer | Required interim behavior |
|---|---|---|---|
| Mempool feed | Phase 11 consensus monitor | Phase 3 front-running detector | Phase 3 creates a disabled typed interface/tests only; do not claim live detection before Phase 11. |
| Forensic case-opened event | Phase 6 AVS consensus | Phase 10 DFIR workflow | Define and version event schema; preserve event safely until Phase 10 consumes it. |
| Pipeline evidence staging | Phase 7 deploy/abort | Phase 10 evidence vault | Store protected staging artifacts; do not call them sealed evidence before Phase 10. |
| On-chain tracing | Phase 10 forensics | Phase 13 compliance screening | Use fixtures/local adapters until the integration is verified. |
| Executive reporting | Zones 3–8 + benchmarks | Phase 14 Zone 9 report | Validate renderer with synthetic sanitized JSON before real aggregation exists. |

## Required workflow for each focused thread

1. Start with this `HANDOFF.md`, the relevant `CHECKLIST.md` task section, and only the source files/logs relevant to the task.
2. Confirm task ID, scope, files expected to change, acceptance criteria, and validation commands.
3. Implement on the Kali VM; do not treat proposed code as completed until you run validation.
4. Update `docs/CHECKLIST.md` with real outcomes, evidence path, limitations, and commit ID.
5. Update this `docs/HANDOFF.md` with current phase/task, completed work, blockers, and next task.
6. Commit implementation plus documentation together.
7. Open the next thread using the updated two files.

## Required end-of-thread output

Before closing a focused Perplexity thread, request a factual completion record containing:

- Checklist IDs addressed and accurate proposed status
- Scope completed and explicitly not completed
- Files created/modified
- Commands run and results
- Tests/security checks passed, failed, or not run
- Evidence paths and CI job references
- Git commit hash, if available
- Dependencies created/consumed/blocked
- Coursework simulation and limitations
- Exact recommended next task

---

# Handoff update template

Replace the active-state portions of this file after every task or phase completion.

```markdown
## Current position

| Field | Current value |
|---|---|
| Current phase | Phase [N] — [name] |
| Current task | [TASK-ID] — [task title] |
| Current thread | [thread title] |
| Current branch | [branch] |
| Last verified commit | [short hash — message] |
| Last GitLab pipeline | [status / job name] |
| Last updated | [YYYY-MM-DD] |

## Completed since previous handoff

- **[TASK-ID] — [title]:** [factual one- or two-sentence result]
  - Files: `[path]`, `[path]`
  - Validation: `[command]` → [result]
  - Evidence: `[path / CI job]`
  - Commit: `[hash]`
  - Limitations/dependencies: [if any]

## Current task details

### [TASK-ID] — [title]

**Objective**

[Exact objective]

**Expected files**

- `[path]`

**Acceptance criteria**

- [ ] Criterion
- [ ] Criterion

**Validation commands**

```bash
# only commands relevant to this task
```

**Security constraints**

- [Constraint]

## Current blockers / risks

- [Blocker, risk, or “None known”]

## Immediate next task queue

1. `[TASK-ID] — [title]`
2. `[TASK-ID] — [title]`
3. `[TASK-ID] — [title]`
```

# Phase-completion handoff template

Use this when a phase gate has passed:

```markdown
# Phase [N] completion handoff — [Phase name]

## Gate result

- **Status:** ✅ Complete
- **Phase gate verified on:** [date]
- **Gate commit/tag:** [hash/tag]
- **GitLab pipeline/evidence:** [reference]

## Completed checklist items

- [TASK-ID]: [result]
- [TASK-ID]: [result]

## Validation evidence

- [Command/test/CI job]: [factual result]

## Architecture decisions / simulations

- [Decision or documented coursework simulation]

## Open risks / forward dependencies

- [Dependency, producer, consumer, safe interim behavior]

## Next phase

- **Phase:** [N+1]
- **First task:** [TASK-ID]
- **Why it is unblocked:** [reason]
- **Required inputs to attach in the next thread:** `docs/CHECKLIST.md`, this `docs/HANDOFF.md`, [relevant source/config files]
```

## GitLab CI/CD remote baseline

- Status: Local GitLab CE remote configured and SSH authentication verified.
- Scope: Coursework/home-lab simulation; GitLab CE runs in a local Docker container.
- Repository policy: GitLab is the private CI/CD remote. GitHub remains the existing repository remote.
- Security note: No private SSH keys, passphrases, tokens, credentials, or host-specific access details are stored in this repository.
