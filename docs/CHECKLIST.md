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

## Documentation reconciliation requirement


Before a task is marked `✅ Complete and verified` or its completion
documentation is committed, reconcile all applicable records in
`docs/CHECKLIST.md`, `docs/HANDOFF.md`, and `docs/RUNBOOK.md`. The tracker row,
detailed task state, every required acceptance checkbox, HANDOFF current
position/current task/completed record, and applicable RUNBOOK procedure status
must agree with factual evidence.


Do not mark a task complete when required acceptance criteria remain unchecked,
when a predecessor task is still labelled current, or when stale wording says
documentation, CI, publication, or synchronization is pending after the event
has occurred. Run `git diff --check`, inspect the exact documentation diff,
perform a secret-safety review, and keep `docs/.backup/` untracked before
staging.


Use evidence terms precisely: `passed` requires a named successful command,
test, scanner, or CI result; `committed` requires a created local commit;
`published` requires a successful push of that exact commit; and
`synchronized` requires fetched `main`, `gitlab/main`, and `origin/main` to
resolve to the same full SHA.


## Project state

| Field | Current value |
|---|---|
| Current phase | Phase 1 — Skeleton scaffold |
| Current task | P01-001 — Unpack/create the project skeleton in the Kali VM project directory |
| Current thread | Phase 0 is complete and verified through the synchronized P00-GATE evidence commit `983098a34511ba06157268feda9f0f02c15eac63`; Phase 1 has not started. Preserve protected signing material, evidence-vault boundaries, and untracked `docs/.backup/`. |
| Current branch | `main` |
| Last verified commit | `983098a34511ba06157268feda9f0f02c15eac63` — `docs(phase-00): reconcile P00 gate evidence` |
| Last GitLab pipeline | Passed for `983098a34511ba06157268feda9f0f02c15eac63` (pipeline identifier not captured) |
| Last GitHub post | Posted — `origin/main` resolved to `983098a34511ba06157268feda9f0f02c15eac63` |
| Synchronization | Verified — `main == gitlab/main == origin/main == 983098a34511ba06157268feda9f0f02c15eac63` |
| Runtime state | Empty local ext4 evidence vault exists at `/srv/blockchain-soc/evidence-vault`; P00-013 raw evidence remains unchanged in the shared transfer location. |
| Last updated | 2026-10-03 |
| Project workspace | Autonomous AI-Native Blockchain SOC — Enterprise V10.3 |

---

## Phase dashboard

| Phase | Name | Status | Phase gate evidence | Commit / tag |
|---:|---|---|---|---|
| 0 | Environment and prerequisites | ✅ | P00-GATE locally validated; `983098a34511ba06157268feda9f0f02c15eac63` synchronized across local, GitLab, and GitHub; phase-declaration documentation lifecycle pending. | `983098a34511ba06157268feda9f0f02c15eac63` |
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
| P00-001 | Update the Kali Linux VM. | ✅ | Verified 2026-09-28: Kali update/baseline evidence recorded; documentation commit `6e6d9baf744495039e0271a19f170cf40b29a639` synchronized across local, GitLab, and GitHub. |
| P00-002 | Install and verify Git, Node.js/npm, Python 3.11+, pip, Docker, and Docker Compose on Kali. | ✅ | Verified 2026-09-28: local prerequisite validation passed; documentation/evidence commit `bd7d284c50debf43330504721dea77bb8252d804` posted to GitLab and GitHub; GitLab pipeline #12 passed; `main`, `gitlab/main`, and `origin/main` resolved to the same SHA. |
| P00-003 | Install and verify Foundry (`forge`, `anvil`, `cast`) and Hardhat. | ✅ | Verified 2026-09-28: Foundry 1.8.3 and Hardhat 2.29.1 validated; commit `473793554ceb7898b4b2165dfef401c47fa14d50`; GitLab Pipeline #13 passed; `main`, `gitlab/main`, and `origin/main` resolved to the same SHA. |
| P00-004 | Install and verify Slither, Mythril, and Certora CLI, or document the Certora API-key alternative. | ✅ | Verified 2026-09-30: Slither 0.11.6, Mythril v0.24.8, and Certora CLI 8.19.2 validated. Documentation commit `3a3e2f936200e5324165304b7ac5ffbb3b6f31ba`; GitLab Pipeline #15 passed; the same commit was posted to GitHub; `main`, `gitlab/main`, and `origin/main` resolved to the same SHA. |
| P00-005 | Install Ollama on Windows and record the approved local model set. | ✅ | Verified 2026-09-30: Ollama 0.34.4 and final four-model local set validated; redundant `deepseek-r1:32b` removed; documentation commit `afb049f37ad850f67c3dbc534a892b69634f5a1c`; GitLab Pipeline #18 passed; `main`, `gitlab/main`, and `origin/main` resolved to the same SHA. |
| P00-006 | Bind Ollama to loopback/non-default local port and configure a reverse proxy on the private interface at port 11434. | ✅ | Verified 2026-10-01: loopback backend and private-interface proxy validated; documentation commit `f9856ed4c181cb6740e7f26043e96a54d3ec0853`; GitLab Pipeline #20 passed; `main`, `gitlab/main`, and `origin/main` resolved to the same SHA. |
| P00-007 | Generate private CA, server certificate, and client certificate for Kali-to-Windows mTLS. | ✅ | Verified 2026-10-01: private CA, Windows server certificate, and Kali client certificate created only in host-local protected storage; certificate chain/purpose and key/certificate matching checks passed; Caddy mTLS static validation passed without starting Caddy or Ollama; documentation commit `3eb7d51225622833d7813d64bb9dd343ad8e3f62`; GitLab Pipeline #23 passed; `main`, `gitlab/main`, and `origin/main` resolved to the same SHA. |
| P00-008 | Require a bearer token at the reverse proxy and ensure Ollama itself is not directly exposed on the LAN. | ✅ | Verified 2026-10-02: host-local bearer verifier enforced authorization before proxying; Ollama and verifier were loopback-only during the approved temporary test; valid mTLS without Bearer returned HTTP 401; no secret was committed or documented. |
| P00-009 | Verify Kali can make an authenticated mTLS request to the Windows Ollama proxy. | ✅ | Verified 2026-10-02: Kali-to-Windows hostname/SNI-aligned mTLS request was rejected without a client certificate; with the approved client certificate and valid Bearer token, the verifier recorded allow. GET / returned HTTP 403 after authorization, so an authenticated GET /api/tags success response remains an optional functional follow-up. |
| P00-010 | Audit and document the existing private GitLab remote and GitLab CI/CD source-of-truth policy; do not create duplicate infrastructure. | ✅ | Verified 2026-10-02: read-only audit confirmed the existing GitLab remote and tracked CI smoke configuration; evidence commit `e735198dcf25d186d659313520976d342d973380` passed GitLab CI, was pushed to GitHub, and `main`, `gitlab/main`, and `origin/main` resolved to the same SHA. |
| P00-011 | Prepare the GitHub account/public-mirror policy; do not configure automatic public mirroring. | ✅ | Verified 2026-10-02: read-only audit established GitLab as the private CI/CD source-of-truth remote and GitHub as a manually synchronized secondary remote; no repository-tracked GitHub automation or local mirror configuration was found. Documentation closeout commit `e01d36a5de7a61bf4821b4895ecb35f149a1ba38` passed GitLab CI, was posted to GitHub, and was verified synchronized as `main == gitlab/main == origin/main == e01d36a5de7a61bf4821b4895ecb35f149a1ba38`. |
| P00-012 | Install DFIR tooling: Sleuth Kit, optional Autopsy GUI, Volatility 3, Plaso, dc3dd, libewf-tools, YARA, tshark/tcpdump, optional Zeek, and GPG or minisign. | ✅ | Verified 2026-10-02: Sleuth Kit 4.14.0, Autopsy 2.24-6kali1, Volatility 3 2.28.2 via pipx (`vol`), Plaso 20260119-1kali1, dc3dd 7.3.1-4, ewf-tools 20140816-2+b2, YARA 4.5.8, tshark 4.6.6, tcpdump 4.99.6, GnuPG 2.4.9, and minisign 0.12 (`0.12-1+b1`) safely version/help validated. Optional Zeek remains blocked by the available Kali package dependency `libc6 < 2.38` versus installed `libc6 2.43-4`. Documentation closeout commit `3fa2735ee251f90a4dc46619e6bf85ebae0371c6` passed GitLab CI (green observed; pipeline identifier not captured), was posted to GitHub, and final verification proved `main == gitlab/main == origin/main == 3fa2735ee251f90a4dc46619e6bf85ebae0371c6`. |
| P00-013 | Select and test a memory-acquisition method on a throwaway VM: VirtualBox core dump, LiME, or AVML. | ✅ | Verified 2026-10-03: disposable Ubuntu memory-image acquisition and Volatility 3 banner/`linux.pslist`/`linux.pstree` validation completed. Evidence commit `cd7731af8a5c50637e8d0ba3d6b624e68d04e97a` passed GitLab CI, was posted to GitHub, and `main == gitlab/main == origin/main == cd7731af8a5c50637e8d0ba3d6b624e68d04e97a`. |
| P00-014 | Prepare a dedicated evidence-vault directory/volume with separate service-account ownership; optionally document MinIO Object Lock. | ✅ | Verified 2026-10-03: local ext4 vault `/srv/blockchain-soc/evidence-vault` is empty, `soc-evidence:soc-evidence`, mode `0700`; service-account access passed and interactive `kali` listing was denied. Evidence commit `54bde63816abe2f7015b20c87dfc50adcbd98a13` passed GitLab CI, was posted to GitHub, and `main == gitlab/main == origin/main == 54bde63816abe2f7015b20c87dfc50adcbd98a13`. |
| P00-015 | Create an operator signing key for evidence-manifest signing; keep private material outside Git. | ✅ | Verified 2026-10-03: dedicated passphrase-protected Minisign key was created only in protected host-local storage; owner-only permissions were validated; a harmless synthetic manifest was detached-signed and verified; and synthetic artifacts were removed. Documentation closeout commit `f34e97b18cb3cee417d1c2b3fc618ef676271773` was posted to GitLab, reported green in GitLab CI (pipeline identifier not captured), posted to GitHub, and fetched verification proved `main == gitlab/main == origin/main == f34e97b18cb3cee417d1c2b3fc618ef676271773`. |

## P00 — evidence log

### P00-001 — Kali update

- **Status:** ✅ Complete and verified
- **Scope completed:** Kali package-index refresh, full-upgrade verification, broken-package repair check, package audit, held-package check, reboot-required check, OS/kernel baseline capture, documentation update, GitLab post/CI verification, GitHub post, and three-way commit-SHA synchronization.
- **Files changed:** `docs/CHECKLIST.md`, `docs/HANDOFF.md`.
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
  git rev-parse main
  git rev-parse gitlab/main
  git rev-parse origin/main
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
  - Documentation/evidence commit: `6e6d9baf744495039e0271a19f170cf40b29a639`.
  - GitLab documentation pipeline was reported as succeeded; pipeline ID/URL was not captured.
  - GitHub post was completed.
  - Synchronization verification succeeded: `main`, `gitlab/main`, and `origin/main` each resolved to `6e6d9baf744495039e0271a19f170cf40b29a639`.
  - APT reported unused auto-installed packages; `sudo apt autoremove` was intentionally not run because removal is outside P00-001 scope.
- **Evidence path / CI job:** Sanitized Kali terminal evidence in the P00-001 implementation thread; GitLab documentation pipeline reported as succeeded.
- **Git commit:** `6e6d9baf744495039e0271a19f170cf40b29a639`.
- **GitLab post / CI:** Posted to `gitlab/main`; pipeline reported succeeded.
- **GitHub post:** Posted to `origin/main`.
- **Synchronization:** Verified: `main == gitlab/main == origin/main == 6e6d9baf744495039e0271a19f170cf40b29a639`.
- **Security checks:** No secrets, tokens, private keys, raw evidence, or unredacted compliance data were recorded. No unrelated tooling was installed and no packages were removed.
- **Dependencies / limitations:** No coursework simulation applies. GitLab pipeline ID/URL was not captured in the evidence record.
- **Next recommended task:** P00-002 — Install and verify Git, Node.js/npm, Python 3.11+, pip, Docker, and Docker Compose on Kali.

### P00-002 — Core Kali development prerequisites

- **Status:** ✅ Complete and verified.
- **Scope completed:** Verified Git, Node.js/npm, Python 3.11+, pip, Docker Engine, Docker Compose, Docker daemon health, and current-user Docker access. Installed only the missing `npm` package after reviewing command resolution, package ownership, APT policy, and package-health output.
- **Scope not completed:** P00-003 and later Phase 0 tools; Docker Compose application-stack startup; application-code work; privileged containers; host networking; host mounts; registry credentials; Docker secrets; and `apt autoremove`.
- **Files changed:** `docs/CHECKLIST.md`, `docs/HANDOFF.md`, `docs/RUNBOOK.md`.
- **Validation commands:**
  ```bash
  git --version
  node --version
  npm --version
  python3 --version
  python3 -m pip --version
  docker --version
  docker compose version
  systemctl is-active docker
  docker info
  docker run --rm hello-world
  command -v node
  command -v npm
  dpkg -S "$(command -v node)"
  dpkg-query -W -f='${binary:Package}\t${Version}\t${Status}\n' nodejs npm
  apt-cache policy nodejs npm
  dpkg --audit
  apt-mark showhold
  git push gitlab main
  git push origin main
  git fetch gitlab
  git fetch origin
  git rev-parse main
  git rev-parse gitlab/main
  git rev-parse origin/main
  ```
- **Factual results:**
  - Initial verification found Git `2.53.0`, Node.js `v24.19.0`, Python `3.14.7`, pip `26.1.2`, Docker Engine `29.8.1`, and Docker Compose `v5.5.1`.
  - Initial `npm --version` returned `zsh: command not found: npm`; `npm` package state was `unknown ok not-installed`.
  - `/usr/bin/node` belongs to installed Kali package `nodejs 24.19.0+dfsg+~cs24.13.3-1`; APT candidate for npm was `12.0.2+ds1-2`.
  - `sudo apt install npm` completed successfully. Post-install checks returned npm `12.0.2` at `/usr/bin/npm`; package state was `npm 12.0.2+ds1-2 install ok installed`.
  - `dpkg --audit` and `apt-mark showhold` produced no output after installation.
  - `systemctl is-active docker` returned `active`; `docker info` returned Docker client and server information without `sudo`.
  - `docker run --rm hello-world` completed successfully without privileged mode, host networking, host mounts, or Docker secrets.
  - Documentation/evidence commit: `bd7d284c50debf43330504721dea77bb8252d804`.
  - GitLab pipeline #12 passed for the P00-002 documentation/evidence commit.
  - GitHub post completed.
  - Synchronization verification succeeded: `main`, `gitlab/main`, and `origin/main` each resolved to `bd7d284c50debf43330504721dea77bb8252d804`.
- **Evidence path / CI job:** Sanitized Kali terminal evidence in the P00-002 implementation thread; GitLab pipeline #12 passed.
- **Git commit:** `bd7d284c50debf43330504721dea77bb8252d804`.
- **GitLab post / CI:** Posted to `gitlab/main`; pipeline #12 passed.
- **GitHub post:** Posted to `origin/main`.
- **Synchronization:** Verified: `main == gitlab/main == origin/main == bd7d284c50debf43330504721dea77bb8252d804`.
- **Security checks:** No passwords, tokens, private keys, mTLS keys, wallet material, raw evidence, or unredacted compliance data were recorded. No privileged containers, host networking, host mounts, registry credentials, Docker secrets, or `apt autoremove` were used.
- **Dependencies / limitations:** P00-002 unblocks P00-003. Docker Compose application-stack startup remains explicitly deferred to P01-006. No coursework simulation applies to local prerequisite validation.
- **Runbook impact:** Updated in `bd7d284c50debf43330504721dea77bb8252d804` with the P00-002 prerequisite-validation procedure.
- **Next recommended task:** P00-003 — Install and verify Foundry (`forge`, `anvil`, `cast`) and Hardhat.

### P00-003 — Foundry and Hardhat prerequisites

- **Status:** ✅ Complete and verified.
- **Scope completed:** Installed Foundry through verified `foundryup`; verified `forge`, `anvil`, and `cast`; added a guarded user-local zsh PATH block for `/home/kali/.config/.foundry/bin`; installed only the repository-declared npm devDependencies after approved dry-run review; generated `package-lock.json`; and locally verified project-local Hardhat.
- **Scope not completed:** P00-004 and later tasks; Slither, Mythril, Certora, DFIR tooling, Ollama, mTLS, Windows configuration, Docker Compose application startup, application-code/configuration work, project test suites, scanners, persistent Anvil operation, RPC/wallet activity, privileged containers, host networking, host mounts, registry credentials, Docker secrets, and `apt autoremove`.
- **Files changed:** `package-lock.json`, `docs/CHECKLIST.md`, `docs/HANDOFF.md`, and `docs/RUNBOOK.md`. User-local `~/.zshrc` was updated outside the repository to persist the Foundry PATH.
- **Validation commands:**
  ```bash
  curl -L https://foundry.paradigm.xyz | bash
  export PATH="$PATH:/home/kali/.config/.foundry/bin"
  foundryup
  forge --version
  anvil --version
  cast --version
  forge init --no-git /tmp/p00-003-foundry-smoke.Bg7RMq
  forge build
  cast to-wei 1 ether
  npm install --dry-run --ignore-scripts --no-audit --no-fund
  npm install --ignore-scripts --no-audit --no-fund
  npm ls --depth=0
  npx --no-install hardhat --version
  ./node_modules/.bin/hardhat --version
  zsh -ic 'forge --version; anvil --version; cast --version'
  git push gitlab main
  git push origin main
  git fetch gitlab
  git fetch origin
  git rev-parse main
  git rev-parse gitlab/main
  git rev-parse origin/main
  ```
- **Factual results:**
  - `foundryup 0.0.8` installed at `/home/kali/.config/.foundry/bin/foundryup`; installer output reported attestation and binary-integrity verification.
  - `foundryup` installed Foundry `v1.8.3`; installer output verified `forge`, `cast`, and `anvil`.
  - `forge`, `anvil`, and `cast` each reported version `1.8.3`, build commit `cae51ad458f6abb64852b7709eb784352429825d`.
  - A fresh interactive zsh session resolved the Foundry tools through the guarded `~/.zshrc` PATH block.
  - A disposable Foundry project initialized without Git; `forge build` compiled 23 files with Solc `0.8.37`; `cast to-wei 1 ether` returned `1000000000000000000`.
  - The disposable workspace `/tmp/p00-003-foundry-smoke.Bg7RMq` was removed and its absence was verified.
  - Approved npm dry run resolved 227 packages. The real install used `--ignore-scripts --no-audit --no-fund` and added 227 packages.
  - `package-lock.json` reports lockfile version `3`, root Hardhat range `^2.22.0`, resolved Hardhat `2.29.1`, TypeScript `5.9.3`, and tsx `4.23.15`.
  - The local executable `node_modules/.bin/hardhat` exists; `npx --no-install hardhat --version` and the direct local binary each returned `2.29.1`.
  - `package.json` had no diff; `node_modules/` is ignored; `package-lock.json` is tracked.
  - npm emitted deprecation warnings for transitive `glob@10.5.0` and `uuid@8.3.2`; remediation/audit is deferred because it is outside P00-003 scope.
  - Documentation/lockfile commit `473793554ceb7898b4b2165dfef401c47fa14d50` was pushed to `gitlab/main`.
  - GitLab Pipeline #13 passed for commit `473793554ceb7898b4b2165dfef401c47fa14d50`.
  - The same commit was pushed to `origin/main`.
  - Fetched synchronization verification succeeded: `main`, `gitlab/main`, and `origin/main` each resolved to `473793554ceb7898b4b2165dfef401c47fa14d50`.
- **Evidence path / CI job:** Sanitized Kali terminal evidence in the P00-003 implementation thread; GitLab Pipeline #13 passed.
- **Git commit:** `473793554ceb7898b4b2165dfef401c47fa14d50` — `chore(phase-00): install Foundry and Hardhat prerequisites`.
- **GitLab post / CI:** Posted to `gitlab/main`; Pipeline #13 passed.
- **GitHub post:** Posted to `origin/main`.
- **Synchronization:** Verified: `main == gitlab/main == origin/main == 473793554ceb7898b4b2165dfef401c47fa14d50`.
- **Security checks:** No passwords, tokens, private keys, mTLS keys, wallet material, raw evidence, or unredacted compliance data were recorded. No Docker containers, privileged mode, host networking, host mounts, registry credentials, Docker secrets, persistent Anvil listener, RPC endpoint, wallet/key operation, project test suite, scanner, or `apt autoremove` was used.
- **Dependencies / limitations:** P00-002 unblocked P00-003. The Foundry smoke workspace is a 🔒 coursework/local toolchain simulation, not a production deployment or chain interaction. The user-local Foundry PATH configuration is outside Git.
- **Runbook impact:** P00-003 runbook procedure was added and locally validated; the procedure's original pending label is reconciled in this documentation update using factual commit, GitLab CI, GitHub post, and SHA evidence.
- **Next recommended task:** P00-004 — Install and verify Slither, Mythril, and Certora CLI, or document the Certora API-key alternative.

### P00-004 — Smart-contract security tooling prerequisites

- **Status:** ✅ Complete and verified.
- **Scope completed:** Read-only tool-state inspection; isolated installation of Slither and Certora CLI through pipx; pull and hardened local validation of the Mythril Docker image; safe version/help validation only; a credential-safe Certora API-key alternative check; documentation update; local commit; GitLab-first post; GitLab CI verification; GitHub post; and three-way SHA synchronization.
- **Scope not completed:** Contract scanning, symbolic analysis, formal proof execution, public/external target interaction, Certora API-key configuration, application-code/configuration changes, Docker Compose startup, Windows/Ollama/mTLS work, and `apt autoremove`.
- **Files changed:** `docs/CHECKLIST.md`, `docs/HANDOFF.md`, and `docs/RUNBOOK.md` in documentation commit `3a3e2f936200e5324165304b7ac5ffbb3b6f31ba`. No application source, configuration, dependency manifest, or lockfile changed during local tool installation/validation.
- **Validation commands:**
  ```bash
  command -v slither || true
  slither --version 2>&1 || true
  command -v myth || true
  myth version 2>&1 || true
  myth --version 2>&1 || true
  command -v certoraRun || true
  certoraRun --version 2>&1 || true
  python3 --version 2>&1 || true
  python3 -m pip --version 2>&1 || true
  python3 -m pip show slither-analyzer mythril certora-cli 2>&1 || true
  pipx install slither-analyzer==0.11.6
  pipx install certora-cli==8.19.2
  docker pull mythril/myth:latest
  slither --version
  certoraRun --version
  certoraRun --help
  docker run --rm --network none --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m --tmpfs /home/mythril/.solcx:rw,noexec,nosuid,size=64m --cap-drop ALL --security-opt no-new-privileges mythril/myth:latest myth version
  docker run --rm --network none --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m --tmpfs /home/mythril/.solcx:rw,noexec,nosuid,size=64m --cap-drop ALL --security-opt no-new-privileges mythril/myth:latest myth --help
  ```
- **Factual results:**
  - Initial inspection found no `slither`, `myth`, or `certoraRun` command and no installed `slither-analyzer`, `mythril`, or `certora-cli` pip package metadata.
  - Python was `3.14.7`; pip was `26.1.2`; pipx was `1.15.0`.
  - `pipx install slither-analyzer==0.11.6` completed; `/home/kali/.local/bin/slither` resolved through the isolated pipx environment; `slither --version` returned `0.11.6`.
  - `pipx install certora-cli==8.19.2` completed; `/home/kali/.local/bin/certoraRun` resolved through the isolated pipx environment; `certoraRun --version` returned `certora-cli 8.19.2`; local help rendered.
  - `docker pull mythril/myth:latest` completed. Local image inspection reported digest `sha256:49e11758e359d0b410f648df5bbcba28a52e091a78e4772b5c02b9043666b4ff`.
  - A hardened no-network, read-only Mythril container with disposable tmpfs mounts returned `Mythril version v0.24.8`; `myth --help` rendered. Matplotlib emitted a non-fatal temporary-cache warning under the permitted `/tmp` tmpfs.
  - Certora environment inspection reported `CERTORAKEY_STATUS=not_set`; no key value was requested, printed, stored, or committed, and no proof execution was attempted.
  - Repository boundary checks before and after installation/validation showed only intentional untracked `docs/.backup/`; no tracked project diff was produced.
- **Evidence path / CI job:** Sanitized Kali terminal evidence in the P00-004 implementation thread; GitLab Pipeline #15 passed for commit `3a3e2f936200e5324165304b7ac5ffbb3b6f31ba`, with one stage completed in 5 seconds.
- **Git commit:** `3a3e2f936200e5324165304b7ac5ffbb3b6f31ba` — `docs(phase-00): record smart-contract security tooling validation`.
- **GitLab post / CI:** Posted to `gitlab/main`; GitLab Pipeline #15 passed.
- **GitHub post:** Posted to `origin/main`.
- **Synchronization:** Verified: `main == gitlab/main == origin/main == 3a3e2f936200e5324165304b7ac5ffbb3b6f31ba`.
- **Security checks:** No contract scan, target address, bytecode, source input, RPC request, proof execution, API key, token, password, private key, seed phrase, wallet material, raw evidence, privileged container, host mount, host network, Docker socket mount, or `apt autoremove` was used. Mythril validation used `--network none`, `--read-only`, tmpfs-only writable paths, `--cap-drop ALL`, and `no-new-privileges`.
- **Dependencies / limitations:** P00-002 and P00-003 were documented complete before this task. Certora CLI is locally installed, but actual prover execution requires an authorized personal access key managed outside Git, project files, terminal captures, and this documentation; `CERTORAKEY` was not set during validation. Mythril runs through a local Docker image because its supported pip range does not cover the host Python 3.14 environment.
- **Runbook impact:** Updated and verified in `docs/RUNBOOK.md` with the P00-004 isolated installation and safe version/help validation procedure.
- **Next recommended task:** P00-005 — Install Ollama on Windows and pull the agreed local model set; record actual model names and versions.

### P00-005 — Ollama local-model prerequisite

- **Status:** ✅ Complete and verified.
- **Scope completed:** Read-only inspection of the authorized Windows AI-inference host; factual Ollama installed-state, process/startup state, local listener/API availability, local model inventory, and per-model metadata capture; explicit removal of the redundant `deepseek-r1:32b` tag after approval; post-removal validation of the retained stable DeepSeek tag and final model inventory; documentation update; local commit; GitLab-first post; GitLab CI verification; GitHub post; and three-way SHA synchronization.
- **Scope not completed at the time:** P00-006 through P00-009 controls were outside this P00-005 task: loopback binding, port changes, reverse proxy, firewall changes, LAN exposure controls, mTLS, bearer authorization, and Kali-to-Windows connectivity testing. No Ollama installation or model pull was required or performed. Subsequent P00-006 through P00-009 evidence is recorded in their dedicated entries.
- **Files changed:** `docs/CHECKLIST.md` and `docs/HANDOFF.md` in documentation commit `afb049f37ad850f67c3dbc534a892b69634f5a1c`. `docs/.backup/` remains untracked local recovery material and was not staged or committed.
- **Validation commands:**
  ```powershell
  ollama --version
  ollama list
  ollama show deepseek-r1:32b
  ollama show qwen2.5-coder:32b
  ollama show deepseek-r1:32b-stable
  ollama show qwen3.5:9b
  ollama show qwen3:32b
  ollama rm deepseek-r1:32b
  ollama list
  ollama show deepseek-r1:32b-stable
  ollama show deepseek-r1:32b
  ```
- **Factual results:**
  - Ollama was already installed at `C:\Users\User\AppData\Local\Programs\Ollama\ollama.exe`; `ollama --version` returned `0.34.4`. No installation occurred.
  - Read-only discovery recorded a running `ollama.exe` process, current-user Startup-folder reference, a successful loopback `GET http://127.0.0.1:11434/api/tags` response, and no observed non-loopback established API connection at inspection time.
  - Initial local inventory contained five tags: `deepseek-r1:32b`, `qwen2.5-coder:32b`, `deepseek-r1:32b-stable`, `qwen3.5:9b`, and `qwen3:32b`.
  - Per-model metadata was captured before removal. `deepseek-r1:32b` and `deepseek-r1:32b-stable` each reported Qwen2 architecture, 32.8B parameters, 131072 context length, 5120 embedding length, and `Q4_K_M` quantization; the stable tag included a `num_ctx 4096` override.
  - After explicit approval, `ollama rm deepseek-r1:32b` returned `deleted 'deepseek-r1:32b'`.
  - Final retained approved local model set: `qwen2.5-coder:32b` (19 GB), `deepseek-r1:32b-stable` (19 GB), `qwen3.5:9b` (6.6 GB), and `qwen3:32b` (20 GB).
  - Post-removal `ollama show deepseek-r1:32b-stable` succeeded; `ollama show deepseek-r1:32b` returned `Error: model 'deepseek-r1:32b' not found`.
- **Evidence path / CI job:** Sanitized Windows PowerShell evidence in the P00-005 implementation thread; GitLab Pipeline #18 passed for `afb049f37ad850f67c3dbc534a892b69634f5a1c`.
- **Git commit:** `afb049f37ad850f67c3dbc534a892b69634f5a1c` — `docs(phase-00): record P00-005 Ollama model validation`.
- **GitLab post / CI:** Posted to `gitlab/main`; GitLab Pipeline #18 passed.
- **GitHub post:** Posted to `origin/main`.
- **Synchronization:** Verified: `main == gitlab/main == origin/main == afb049f37ad850f67c3dbc534a892b69634f5a1c`.
- **Security checks:** No passwords, tokens, API keys, private keys, certificates, seed phrases, wallet material, raw evidence, or unredacted compliance data were recorded. No firewall, listener, port, environment-variable, startup/service, proxy, mTLS, bearer-authentication, network-exposure, remote-model-endpoint, project-source, or Docker Compose change occurred.
- **Dependencies / limitations:** P00-001 through P00-004 were complete before this task. The four retained tags are local prerequisite inventory only; model output remains a hypothesis rather than evidence. P00-006 through P00-009 were future controls at the time of this P00-005 record; their later evidence is recorded in their dedicated entries.
- **Runbook impact:** Not updated in this correction-limited closeout; the current allowed tracked-file scope is `docs/CHECKLIST.md` and `docs/HANDOFF.md` only.
- **Next recommended task:** P00-006 — Bind Ollama to loopback/non-default local port and configure a reverse proxy on the private interface at port 11434.

### P00-006 — Loopback Ollama binding and private-interface reverse proxy

- **Status:** ✅ Complete and verified.
- **Scope completed:** On the authorized Windows inference host, ran Ollama as a normal-user foreground process bound only to `127.0.0.1:11435`. Configured and ran Caddy as a normal-user foreground reverse proxy bound only to the approved private interface at port `11434`, forwarding to `127.0.0.1:11435`. Caddy administration was disabled for the validated process.
- **Scope not completed:** Persistent Windows service or startup configuration, Windows Firewall changes, Docker Desktop/Open WebUI startup or configuration, mTLS private CA/certificates, bearer-token authorization, Kali-to-Windows cross-host testing, and internet exposure.
- **Files changed:** `docs/CHECKLIST.md`, `docs/HANDOFF.md`, and `docs/RUNBOOK.md`. Host-local proxy configuration remains untracked runtime configuration.
- **Validation commands:**
  ```powershell
  Invoke-RestMethod http://127.0.0.1:11435/api/tags
  Get-NetTCPConnection -State Listen
  caddy validate --config <host-local-Caddyfile> --adapter caddyfile
  Invoke-RestMethod http://192.168.0.189:11434/api/tags
  ```
- **Factual results:** Ollama listener inspection showed exactly `127.0.0.1:11435`; direct backend health returned four models. Caddy validation returned `Valid configuration`; Caddy listener inspection showed exactly `192.168.0.189:11434`; Caddy administration was disabled. Local proxy health succeeded and proxied `/api/tags` returned four models.
- **Evidence path / CI job:** Sanitized Windows PowerShell evidence in the P00-006 implementation thread; GitLab Pipeline #20 passed for the documentation/evidence commit.
- **Git commit:** `f9856ed4c181cb6740e7f26043e96a54d3ec0853` — `docs(phase-00): record P00-006 proxy validation`.
- **GitLab post / CI:** Posted to `gitlab/main`; GitLab Pipeline #20 passed.
- **GitHub post:** Posted to `origin/main`.
- **Synchronization:** Verified: `main == gitlab/main == origin/main == f9856ed4c181cb6740e7f26043e96a54d3ec0853`.
- **Security checks:** No Docker/Open WebUI startup, firewall change, mTLS material, bearer token, Kali cross-host request, model pull/removal, secret, private key, certificate, credential, raw evidence, or unredacted compliance data was created, printed, or committed.
- **Dependencies / limitations:** P00-005 supplied the approved four-model inventory. The validated arrangement uses normal-user foreground processes and is not persistent across terminal closure, logoff, or restart. Plain HTTP is intentionally temporary; P00-007 and P00-008 add mTLS and bearer authorization before P00-009 cross-host validation.
- **Runbook impact:** Updated in `docs/RUNBOOK.md` with the verified Windows Ollama/Caddy startup, validation, shutdown, and troubleshooting procedure.
- **Next recommended task:** P00-007 — Generate private CA, server certificate, and client certificate for Kali-to-Windows mTLS.

### P00-007 — Private CA, server certificate, client certificate, and Caddy mTLS static validation

- **Status:** ✅ Complete and verified.
- **Scope completed:** Created a private coursework CA, a Windows proxy server certificate, and a Kali client certificate in protected host-local storage outside Git. Configured the Windows-local Caddyfile to present the server certificate, require and verify client certificates against the private CA, disable Caddy administration and automatic HTTPS, and reverse-proxy only to the loopback backend.
- **Scope not completed at the time:** Bearer-token authorization (P00-008), Kali-to-Windows authenticated mTLS inference (P00-009), Caddy/Ollama service startup, live listener verification after the mTLS configuration change, firewall changes, Docker/Open WebUI work, and internet exposure. The later approved P00-008/P00-009 temporary validation evidence is recorded below.
- **Files changed:** `docs/CHECKLIST.md`, `docs/HANDOFF.md`, and `docs/RUNBOOK.md`. PKI material and the host-local Caddyfile remain outside Git.
- **Validation commands actually run:** Kali CA self-verification; Kali client chain validation with `openssl verify -purpose sslclient`; Windows server chain validation with `openssl verify -purpose sslserver`; public-key hash comparisons confirming both private key/certificate pairs match; protected-directory permission/ACL inspection; Kali NTP synchronization verification; Windows `caddy validate --config <host-local-Caddyfile> --adapter caddyfile`.
- **Factual results:** CA self-verification succeeded. Kali client certificate validation and key/certificate match succeeded. Windows server certificate validated against the private CA for server purpose, included the approved private-interface IP in its subject alternative name, and matched its private key. Kali time synchronization was active and synchronized. Caddy static validation returned `Valid configuration` and recognized mandatory TLS client authentication. Caddy and Ollama were not started for this task; no endpoint listener or authenticated cross-host request was made.
- **Evidence path / CI job:** Sanitized Kali and Windows terminal evidence in the P00-007 implementation thread; GitLab Pipeline #23 passed for the documentation/evidence commit.
- **Git commit:** `3eb7d51225622833d7813d64bb9dd343ad8e3f62` — `docs(phase-00): record P00-007 mTLS static validation`.
- **GitLab post / CI:** Posted to `gitlab/main`; GitLab Pipeline #23 passed.
- **GitHub post:** Posted to `origin/main`.
- **Synchronization:** Verified: `main == gitlab/main == origin/main == 3eb7d51225622833d7813d64bb9dd343ad8e3f62`.
- **Security checks:** No private key, certificate body, CSR body, password, token, bearer credential, or raw secret-bearing output was committed. PKI material remains in protected host-local storage. The CA private key is not referenced by Caddy. Repository scans found no common PKI artifact files. Temporary shared-folder certificate copies were removed before final validation.
- **Dependencies / forward references:** P00-006 supplied the loopback backend and private-interface proxy separation. P00-008 and P00-009 were deferred at the time of this static-validation record; their later approved temporary validation evidence is recorded below. The previously deferred Caddy trust-pool migration and formatting maintenance are recorded in the addendum below.
- **Runbook impact:** Verified P00-007 host-local PKI and Caddy static-validation procedure is recorded in `docs/RUNBOOK.md`; it explicitly does not authorize service startup or live network testing.
- **Coursework simulation / limitations:** Coursework/development configuration only; no production certificate lifecycle, revocation service, persistent Windows service, firewall validation, live mTLS handshake, bearer authorization, or inference request was performed.
- **Next recommended task at the time:** P00-008 — Require a bearer token at the reverse proxy and ensure Ollama itself is not directly exposed on the LAN. P00-008/P00-009 are now documented as completed below.

#### P00-007 maintenance addendum — Caddy trust-pool migration and formatting

- **Status:** ✅ Host-local maintenance validated; repository synchronization pending.
- **Scope completed:** Replaced the deprecated Caddy `trusted_ca_cert_file` setting with `trust_pool file` in the host-local Caddyfile and applied Caddy formatting. Created a timestamped host-local backup of the resulting validated Caddyfile.
- **Validation commands actually run:** Temporary candidate validation; `caddy fmt`; final `caddy validate --config <host-local-Caddyfile> --adapter caddyfile`; backup/live SHA-256 comparison; process/listener recheck.
- **Factual results:** The temporary candidate and final formatted live configuration each returned `Valid configuration` with exit code `0`. The deprecated-trust-field and formatting warnings were absent after maintenance. The final Caddyfile and its timestamped backup had identical SHA-256 `22D8195FD727267B36EB7C6CEC16E660C09ABFC5A0C71A02C8E58F46C48312F7`. Caddy and Ollama were not started; no listeners on ports `11434` or `11435` were present.
- **Security checks:** No secret, certificate/key body, token, password, firewall rule, service start, or cross-host request was created or exposed. The Caddyfile remains host-local and outside Git. Its local ACL permits ordinary users to read the file; it must not contain plaintext bearer secrets in P00-008.
- **Git commit / CI / synchronization:** Pending for this documentation maintenance update. Historical P00-007 validation evidence remains recorded above.

### P00-008 — Bearer authorization and loopback-only backend protection

- **Status:** ✅ Complete and verified.
- **Scope completed:** Implemented host-local Bearer-token authorization through the loopback-only forward-auth verifier while preserving the Caddy mTLS gateway and loopback-only Ollama backend.
- **Factual results:** Caddy static validation succeeded with strict SNI/Host enforcement enabled for client authentication. During the approved temporary test, Ollama listened only on `127.0.0.1:11435` and the verifier only on `127.0.0.1:11436`; direct Kali connections to those backend ports timed out. A valid mTLS request without a Bearer credential returned HTTP `401`. The verifier recorded an allow decision when the configured Bearer credential was supplied.
- **Security checks:** No token, private key, certificate body, or raw secret-bearing output was committed or documented. Temporary test processes were stopped, test listeners were released, and the temporary clipboard transfer was overwritten and verified with a harmless marker.
- **Dependencies / limitations:** The server certificate was reissued under the existing private CA with `DNS:ollama-mtls.home.arpa` and `IP:192.168.0.189` SANs to align Caddy strict SNI/Host enforcement with the test hostname. The authenticated request crossed the Kali-to-Windows boundary and is documented under P00-009.
- **Next recommended task:** Continue with the authoritative Phase 0 sequence after reviewing the P00-009 transport/auth-path validation record.

### P00-009 — Authenticated Kali-to-Windows mTLS and Bearer transport-path validation

- **Status:** ✅ Complete and verified.
- **Scope completed:** Performed the approved temporary cross-host validation through the hostname/SNI-aligned Caddy gateway using the CA-verified Kali client certificate and the host-local Bearer verifier.
- **Factual results:** Without a client certificate, the TLS handshake failed with a certificate-required alert and no HTTP response. With valid mTLS but no Bearer credential, Caddy returned HTTP `401`. With valid mTLS and the configured Bearer credential, the Windows verifier recorded an allow decision. The request to `GET /` then returned HTTP `403`; this is recorded as a route/backend response after authorization, not as a Bearer-token rejection.
- **Security checks:** Kali used explicit private resolution for the gateway hostname; no permanent DNS, firewall, startup, or service change was made. Ollama and verifier were not LAN-accessible. The temporary stack was stopped after testing.
- **Dependencies / limitations:** A successful application-level Ollama API response was not established because the authenticated request used the root route. If required later, perform one separately approved temporary request to `GET /api/tags` through the same protected path, then clean up.
- **Next recommended task:** Continue the authoritative Phase 0 order; the optional `/api/tags` confirmation is not required to preserve the verified mTLS and Bearer enforcement evidence.

### P00-010 — GitLab remote and CI/CD source-of-truth audit

- **Status:** ✅ Complete and verified.
- **Scope completed:** Performed a read-only audit of the existing private GitLab remote, GitHub secondary remote, committed root `.gitlab-ci.yml`, current branch/ref state, GitLab reachability, and GitLab-first/GitHub-second synchronization policy. No duplicate infrastructure was created.
- **Scope not completed:** No GitLab project, remote, runner, token, CI/CD variable, visibility setting, branch-protection rule, pipeline definition, or CI configuration was created, changed, or deleted. No P00-011 GitHub-policy work was performed.
- **Files changed:** `docs/CHECKLIST.md` and `docs/HANDOFF.md` in evidence commit `e735198dcf25d186d659313520976d342d973380`. `docs/RUNBOOK.md` update was not required because no user-executable operational procedure changed.
- **Validation commands:** `git remote -v`; `git remote get-url gitlab`; `git remote get-url --push gitlab`; `git remote get-url origin`; `git remote get-url --push origin`; `git fetch --prune gitlab`; `git fetch --prune origin`; `git rev-parse main`; `git rev-parse gitlab/main`; `git rev-parse origin/main`; `git ls-files .gitlab-ci.yml`; `sed -n '1,260p' .gitlab-ci.yml`; `git grep` for tracked CI includes/references; `git ls-remote --heads gitlab main`; GitLab CI status review; `git push origin main`; and final fetched three-way SHA comparison.
- **Factual results:** The existing GitLab fetch/push remote is `gitlab-soc:root/blockchain-security-project-remastered.git`; the existing GitHub fetch/push remote is `git@github.com:ali4210/Blockchain-Security-Project-Remastered.git`. At audit time, `main`, `gitlab/main`, and `origin/main` each resolved to `1c1144be9a35423f41c5c4a8962751fe6a9299a9`, and `git ls-remote --heads gitlab main` returned that SHA for `refs/heads/main`. The tracked root `.gitlab-ci.yml` defines one `verify` stage and `runner_smoke_test`, uses the existing `soc-docker` runner tag, emits CI metadata, checks `README.md`, `docs/CHECKLIST.md`, and `docs/HANDOFF.md`, and runs `uname -a`. No tracked CI include references were found. Evidence commit `e735198dcf25d186d659313520976d342d973380` passed GitLab CI, was pushed to GitHub, and final fetched verification resolved `main`, `gitlab/main`, and `origin/main` to that same SHA.
- **Evidence path / CI job:** Sanitized P00-010 Kali terminal audit output; committed `.gitlab-ci.yml`; GitLab CI passed for evidence commit `e735198dcf25d186d659313520976d342d973380`; final GitHub push and fetched three-way SHA output.
- **Git commit / CI / synchronization:** Evidence commit `e735198dcf25d186d659313520976d342d973380` — `docs(phase-00): record GitLab CI source-of-truth audit` — passed GitLab CI, was pushed to `origin/main`, and was verified synchronized as `main == gitlab/main == origin/main == e735198dcf25d186d659313520976d342d973380`.
- **Security checks:** No password, token, runner registration/authentication token, SSH private key, CI/CD variable value, credential-helper detail, or secret-bearing output was displayed or committed. `docs/.backup/` remains untracked local recovery material.
- **Dependencies / limitations:** GitLab runner hardening, Docker isolation verification, no-privileged-mode enforcement, no-host-mount enforcement, Auto DevOps policy, and broader DevSecOps jobs remain deferred to their planned phases. No coursework simulation was newly introduced by this read-only audit.
- **Next recommended task at P00-010 closeout:** P00-011 — Prepare the GitHub account/public-mirror policy; do not configure automatic public mirroring. The P00-011 read-only audit was completed on 2026-10-02; its documentation closeout is in progress.

### P00-011 — GitHub account/public-mirror policy

- **Status:** ✅ Complete and verified.
- **Scope completed:** Performed a read-only audit of GitHub remote metadata, current refs, tracked GitHub-related automation/policy files, local remote/mirror keys, GitHub reachability, branch state, releases, and tags. Established the policy: GitLab is the private CI/CD source of truth; GitHub is a manually synchronized secondary remote; automatic public mirroring is neither configured nor authorized. Recorded the audit in documentation, committed it, validated the commit in GitLab CI, posted the same commit to GitHub, and verified final three-way SHA synchronization.
- **Scope not completed:** No GitHub account or repository setting, repository visibility, GitHub Action, webhook, secret, deploy key, personal access token, release, tag, branch-protection rule, remote, or mirror configuration was created, changed, or deleted. GitHub website-side visibility, secrets, webhooks, and repository/account settings were intentionally not inspected; their absence is not claimed.
- **Files changed:** `docs/CHECKLIST.md` and `docs/HANDOFF.md` in documentation closeout commit `e01d36a5de7a61bf4821b4895ecb35f149a1ba38`. `docs/RUNBOOK.md` was not required because no verified user-executable GitHub/public-release procedure changed.
- **Validation commands:** `git remote -v`; `git remote get-url origin`; `git remote get-url --push origin`; `git remote get-url gitlab`; `git remote get-url --push gitlab`; `git fetch --prune gitlab`; `git fetch --prune origin`; `git rev-parse main`; `git rev-parse gitlab/main`; `git rev-parse origin/main`; `git ls-remote --heads origin main`; `git ls-files` for `.github/**` and policy files; tracked-reference `git grep`; `.github/workflows` presence check; restricted `git config --get-regexp` for remote/mirror and `branch.main` keys; read-only GitHub account, branch, release, and tag metadata review; `git diff --check`; GitLab pipeline status review; `git push origin main`; and final fetched three-way SHA comparison.
- **Factual results:** Audit date: 2026-10-02. Audit evidence SHA: `b634e287f140b64ffac03d2b58f1f19aee7bc6d8`. GitLab fetch/push remote: `gitlab-soc:root/blockchain-security-project-remastered.git`. GitHub fetch/push remote: `git@github.com:ali4210/Blockchain-Security-Project-Remastered.git`. At audit time, `main`, `gitlab/main`, and `origin/main` all equaled the audit evidence SHA; GitHub advertised `refs/heads/main` at that SHA. No `.github/workflows/` directory was present. The tracked scan returned no GitHub Actions, webhook, mirror, release, Pages, deploy-key, or public-egress automation references. No local `remote.*.mirror`, remote push-URL override, or `branch.main.pushRemote` configuration was returned. GitHub metadata review observed only `main` at the audit evidence SHA, with no releases and no tags. Documentation closeout commit `e01d36a5de7a61bf4821b4895ecb35f149a1ba38` passed GitLab CI, was posted to GitHub, and fetched verification resolved `main`, `gitlab/main`, and `origin/main` to that same SHA.
- **Evidence path / CI job:** Sanitized P00-011 Kali terminal audit output, read-only GitHub metadata observations, GitLab pipeline pass reported for documentation closeout commit `e01d36a5de7a61bf4821b4895ecb35f149a1ba38`, GitHub push output, and final fetched three-way SHA output. Pipeline identifier was not captured.
- **Git commit / CI / synchronization:** Documentation closeout commit `e01d36a5de7a61bf4821b4895ecb35f149a1ba38` passed GitLab CI, was pushed to `origin/main`, and was verified synchronized as `main == gitlab/main == origin/main == e01d36a5de7a61bf4821b4895ecb35f149a1ba38`.
- **Security checks:** No token, password, SSH private key, deploy key, webhook secret, GitHub Actions secret value, credential-helper detail, or browser/session data was displayed or committed. `docs/.backup/` remains untracked local recovery material.
- **Dependencies / forward references:** GitLab remains the private CI/CD source-of-truth remote. GitHub remains a manually synchronized secondary remote. Any future public release or external egress remains human-in-the-loop and subject to the Phase 9 quarantine-egress gate.
- **Coursework simulation / limitations:** This was a repository and remote read-only audit, not a complete GitHub account-security assessment. It does not establish GitHub repository visibility or the absence of GitHub website-side secrets, webhooks, or repository/account settings.
- **Next recommended task:** P00-012 — Install DFIR tooling: Sleuth Kit, optional Autopsy GUI, Volatility 3, Plaso, dc3dd, libewf-tools, YARA, tshark/tcpdump, optional Zeek, and GPG or minisign.

### P00-012 — DFIR tooling baseline

- **Task ID:** P00-012.
- **Status:** ✅ Complete and verified on 2026-10-02. Documentation closeout commit `3fa2735ee251f90a4dc46619e6bf85ebae0371c6` passed GitLab CI (green observed; pipeline identifier not captured), was posted to GitHub, and final verification proved `main == gitlab/main == origin/main == 3fa2735ee251f90a4dc46619e6bf85ebae0371c6`.
- **Scope completed:** Safely version/help validated the required Kali DFIR-tooling baseline: Sleuth Kit 4.14.0; optional Autopsy 2.24-6kali1; Volatility 3 2.28.2 isolated with pipx and exposed as `vol`; Plaso 20260119-1kali1 through its packaged `plaso-*` utilities; dc3dd 7.3.1-4; ewf-tools 20140816-2+b2; YARA 4.5.8; tshark 4.6.6; tcpdump 4.99.6; GnuPG 2.4.9; and minisign package 0.12-1+b1 with CLI version 0.12. Minisign was the sole package newly installed in the final reviewed transaction; GnuPG was already present and only safely validated.
- **Optional-tool limitation:** Zeek was not installed. The available Kali package transaction reported a dependency requiring `libc6 < 2.38`, which conflicts with the installed `libc6 2.43-4`. No forced installation, downgrade, alternate repository, or workaround was attempted.
- **Files changed:** Host-local package and pipx state during implementation; repository documentation closeout changed `docs/CHECKLIST.md`, `docs/HANDOFF.md`, and `docs/RUNBOOK.md` in commit `3fa2735ee251f90a4dc46619e6bf85ebae0371c6`.
- **Validation commands:** Safe package-transaction simulations; package queries; command version/help checks; `minisign -v`; bare `minisign` usage rendering; `dpkg --audit`; `apt-mark showhold`; and repository-boundary `git status --short` checks. No acquisition, capture, analysis, Autopsy launch, signing, verification against case material, key generation, or private-key operation was run.
- **Result:** Minisign installed as the sole new package in its reviewed transaction: 0 upgraded, 1 newly installed, 0 removed, and 0 not upgraded. `dpkg-query` returned `minisign install ok installed 0.12-1+b1`; `minisign -v` returned `minisign 0.12`; bare invocation rendered usage only. `dpkg --audit` returned no findings, and `apt-mark showhold` returned no held packages.
- **Evidence path / CI job:** Sanitized Kali terminal evidence from the P00-012 implementation thread; GitLab pipeline passed with green status for documentation closeout commit `3fa2735ee251f90a4dc46619e6bf85ebae0371c6`; pipeline identifier was not captured; GitHub push and final fetched three-way SHA evidence recorded.
- **Commit:** `3fa2735ee251f90a4dc46619e6bf85ebae0371c6` — `docs(phase-00): record P00-012 DFIR tooling baseline`.
- **Security checks:** No disk, memory, packet, or live-evidence acquisition occurred. No packet capture or network analysis started. Autopsy was not launched. No signing key was generated, imported, exported, or used; no signature was created or verified. No `apt autoremove` was run. No secrets, private keys, credentials, or evidence content were displayed or committed. `docs/.backup/` remains untracked local recovery material.
- **Notes / simulation / limitation:** This is a host-preparation task, not a forensic examination or authorization to collect evidence. Tool version/help validation is not proof that a tool is suitable for a particular evidence format or operational case.

### P00-013 — Memory acquisition and bounded process-structure validation

- **Task ID:** P00-013.
- **Status:** ✅ Complete and verified on 2026-10-03.
- **Scope completed:** Acquired a memory image from the designated disposable Ubuntu lab target and completed limited banner, process-list, and parent/child process-hierarchy validation using Volatility 3.
- **Scope not completed:** No comprehensive malware, hidden-process, module, socket, command-line, open-file, network, or compromise assessment was performed. No clean-host or no-compromise conclusion is made.
- **Files changed:** No tracked repository files during acquisition or analysis. Documentation/evidence commit `cd7731af8a5c50637e8d0ba3d6b624e68d04e97a` changed `docs/CHECKLIST.md` and `docs/HANDOFF.md`; raw evidence, symbols, and analysis logs remain outside Git.
- **Validation commands:** Volatility 3 Framework 2.28.2 banner validation; `linux.pslist`; and `linux.pstree`.
- **Factual results:** The analysis input was `ubuntu-server_P00-013_20261003T055707Z_working.elf`, size `4,317,911,540` bytes, SHA-256 `e5184b85d82f1abb130fc726afecadc7f9b0c298f60b54be1dc6b3b487816f93`. Banner validation exited `0` at `2026-10-03T06:30:47Z`; `linux.pslist` exited `0` at `2026-10-03T06:44:50Z`; and `linux.pstree` exited `0` at `2026-10-03T06:46:14Z`. The Linux process plugins used `Ubuntu_6.8.0-90-generic_6.8.0-90.91_amd64.json.xz`, verified by symbol Git blob SHA-1 `cc2757b589e0af49fde532fc05a4c038c3b4a461`. The observed process list and parent/child hierarchy were plausible for the configured disposable Ubuntu lab host.
- **Evidence path / CI job:** Analysis statuses and logs remain outside Git under `/media/sf_VBox_Files_Shared/P00-013-Analysis/`. Documentation/evidence commit `cd7731af8a5c50637e8d0ba3d6b624e68d04e97a` passed GitLab CI (pipeline identifier not captured), was posted to GitHub, and fetched verification proved `main == gitlab/main == origin/main == cd7731af8a5c50637e8d0ba3d6b624e68d04e97a`.
- **Commit:** `cd7731af8a5c50637e8d0ba3d6b624e68d04e97a` — `docs(phase-00): record P00-013 memory validation`.
- **Security checks:** Raw ELF evidence, symbol archives, analysis logs, credentials, private keys, tokens, and sensitive artifacts are not staged or committed. `docs/.backup/` remains local recovery material and must remain untracked.
- **Dependencies / forward references:** P00-012 supplied Volatility 3. P00-014 is next and must establish the dedicated evidence-vault boundary without altering P00-013 evidence.
- **Runbook impact:** Not required. The supplied evidence validates a bounded result, not a complete reusable operator procedure with tested setup, collection, cleanup, recovery, and troubleshooting steps.
- **Notes / simulation / limitation:** Disposable-lab validation only. This result supports the acquisition-and-analysis workflow but does not establish production readiness or a comprehensive forensic conclusion.

### P00-014 — Evidence-vault service-account isolation and validation

- **Task ID:** P00-014.
- **Status:** ✅ Complete and verified on 2026-10-03.
- **Scope completed:** Created and validated an empty local evidence-vault boundary outside the repository and separate from the VirtualBox shared transfer folder.
- **Scope not completed:** No raw P00-013 evidence was copied, moved, rehashed, sealed, signed, deleted, or modified. No MinIO/Object Lock deployment, object retention policy, evidence admission workflow, chain-of-custody system, signing-key work, or P00-015 task was performed.
- **Files changed:** Host-local system state: the `soc-evidence` system identity and `/srv/blockchain-soc/evidence-vault`. Documentation/evidence commit `54bde63816abe2f7015b20c87dfc50adcbd98a13` changed `docs/CHECKLIST.md` and `docs/HANDOFF.md`.
- **Validation commands:** Read-only storage/mount/permission inspection; guarded system-user/group and vault creation; `stat`; `findmnt`; empty-vault listing as `soc-evidence`; service-account traversal test; denied interactive-user listing test; P00-013 ELF metadata comparison; and repository-boundary `git status --short`.
- **Factual results:** `soc-evidence` is a non-login system identity with UID `999`, GID `966`, home `/nonexistent`, and shell `/usr/sbin/nologin`. `/srv/blockchain-soc` is `root:root` mode `0755`; `/srv/blockchain-soc/evidence-vault` is on local `/dev/sda1` `ext4`, is empty, and is `soc-evidence:soc-evidence` mode `0700`. Service-account traversal passed; the interactive `kali` user was denied vault listing. The P00-013 transfer ELF remained `root:vboxsf`, mode `770`, size `4,317,911,540` bytes before and after validation.
- **Evidence path / CI job:** Sanitized terminal evidence in the P00-014 implementation thread. Documentation/evidence commit `54bde63816abe2f7015b20c87dfc50adcbd98a13` passed GitLab CI (pipeline identifier not captured), was posted to GitHub, and fetched verification proved `main == gitlab/main == origin/main == 54bde63816abe2f7015b20c87dfc50adcbd98a13`.
- **Commit:** `54bde63816abe2f7015b20c87dfc50adcbd98a13` — `docs(phase-00): record P00-014 evidence vault validation`.
- **Security checks:** The vault is outside the Git repository and uses local ext4 ownership/permission enforcement. The VirtualBox `vboxsf` shared folder remains transfer/staging only, not the authoritative vault. Raw ELF evidence, symbols, logs, credentials, private keys, tokens, and `docs/.backup/` are not staged or committed.
- **Dependencies / forward references:** P00-012 supplied DFIR tooling; P00-013 supplied the preserved working-evidence boundary. P00-015 is next.
- **Runbook impact:** Not required. This bounded implementation does not establish a complete reusable procedure for evidence admission, capacity planning, hashing, sealing, custody, retention, recovery, or destruction.
- **Notes / simulation / limitation:** Coursework/local implementation only. The local ext4 filesystem had approximately 8.7 GiB free during preflight; do not transfer the 4.0 GiB P00-013 ELF into the vault without separately approved capacity and integrity controls.

### P00-015 — Operator signing key for evidence-manifest signing

- **Status:** ✅ Complete and verified on 2026-10-03.
- **Scope completed:** Read-only signing-tool and protected-storage discovery; dedicated Minisign key generation in protected host-local storage; permission validation; harmless synthetic detached-signature creation and verification; synthetic-artifact cleanup; repository-boundary checks; documentation closeout; GitLab-first post and reported green CI; GitHub post; and fetched three-way synchronization verification.
- **Files changed:** Host-local protected signing material outside Git; tracked documentation closeout in `docs/CHECKLIST.md`, `docs/HANDOFF.md`, and `docs/RUNBOOK.md`.
- **Validation commands:** Safe system-binary/version and package-ownership inspection; protected-directory metadata inspection; repository ignore-rule checks; interactive Minisign key generation; metadata-only permission validation; synthetic-manifest creation; detached signing; public-key verification; synthetic-artifact cleanup verification; repository status checks; GitLab/GitHub posts; and fetched commit-SHA comparison.
- **Factual results:** Minisign key generation exited `0`. Synthetic detached signing exited `0`; Minisign reported that the signature and comment signature verified; verification exited `0`. The synthetic manifest and signature were confirmed absent after cleanup. Documentation closeout commit `f34e97b18cb3cee417d1c2b3fc618ef676271773` was posted to GitLab, reported green in GitLab CI (pipeline identifier not captured), posted to GitHub, and fetched verification proved `main == gitlab/main == origin/main == f34e97b18cb3cee417d1c2b3fc618ef676271773`.
- **Evidence path / CI job:** Sanitized Kali terminal evidence in the P00-015 implementation thread; GitLab pipeline reported green (pipeline identifier not captured).
- **Commit:** `f34e97b18cb3cee417d1c2b3fc618ef676271773` — `docs(phase-00): record P00-015 signing key validation`.
- **Security checks:** No private-key body, passphrase, recovery material, secret-key identifier, or key content was recorded. No signing material was copied to Git, `docs/.backup/`, shared folders, `/tmp`, or the evidence vault. No raw evidence, P00-013 material, evidence-vault content, repository file, or real evidence manifest was accessed, signed, moved, rehashed, sealed, or modified.
- **Dependencies / limitations:** Dedicated Minisign signing material is host-local only. This task does not define a production evidence-manifest schema, public-key publication/distribution, trust bootstrap, revocation/replacement exercise, or real-evidence signing workflow. Real evidence remains unsigned by this task.
- **Runbook impact:** Updated and verified in `docs/RUNBOOK.md` with the protected key-generation, synthetic sign/verify, cleanup, and failure-boundary procedure; it does not reveal secret material or protected-key location.
- **Next recommended task:** P00-GATE — Audit Phase 0 before beginning Phase 1.

## P00-GATE — Phase 0 completion gate

- [x] `forge --version` succeeds — user-local Foundry `1.8.3`, exit `0`.
- [x] `slither --version` succeeds — `0.11.6`, exit `0`.
- [x] `vol --help` succeeds — exit `0`.
- [x] `fls -V` succeeds — Sleuth Kit `4.14.0`, exit `0`.
- [x] Authenticated mTLS/Bearer transport path from Kali reached the Windows proxy — P00-009 recorded a valid client-certificate plus valid Bearer allow event. This is transport-authorization evidence; authenticated `GET /api/tags` functional success remains an optional follow-up.
- [x] All P00-001 through P00-015 task evidence is recorded above.
- [x] A Phase 0 documentation commit exists — P00-015 closeout `f34e97b18cb3cee417d1c2b3fc618ef676271773` is verified synchronized.
- [x] `docs/HANDOFF.md` is prepared for Phase 1 / P01-001 in this phase-declaration update; final phase declaration remains pending this documentation commit lifecycle.

**Gate status:** ✅ Phase 0 complete and verified by factual gate evidence; phase-declaration documentation commit lifecycle pending.
**Verified by:** Sanitized P00-GATE read-only audit and minimal command validation on 2026-10-03.
**Verification date:** 2026-10-03
**Gate evidence commit/tag:** `983098a34511ba06157268feda9f0f02c15eac63` — GitLab CI reported green (pipeline identifier not captured), GitHub post completed, and fetched verification proved `main == gitlab/main == origin/main == 983098a34511ba06157268feda9f0f02c15eac63`.
**Known observation:** The interactive shell/PATH and prompt integration cannot resolve ordinary utilities such as `git`, `ssh`, `stat`, `wc`, and `less`; gate validation used known absolute paths or a process-local safe `PATH`. This is host-local maintenance work and is not changed by P00-GATE.

---

# Phase 1 — Skeleton scaffold

**Goal:** Establish the complete folder/file skeleton, forensic stubs, dependencies, and green placeholder pipeline. No unrecorded structural decisions after this phase.

| ID | Task | Status | Evidence / commit |
|---|---|---|---|
| P01-001 | Unpack/create the project skeleton in the Kali VM project directory. | ✅ | Complete and verified 2026-10-04: technical reconciliation evidence commit `c6d5017d44eaa2c12f5b2520a6d9d5fe49cfce7e` passed GitLab CI (pipeline ID/URL not captured), was published to GitHub, and final completion-status reconciliation `85b3872c078f8748bee5d3eb3d4d6a7e572f1fff` was also GitLab-CI-passed, published to GitHub, and verified as `main == gitlab/main == origin/main`. |
| P01-002 | Initialize Git and commit the full skeleton with every TODO stub. | ✅ | Complete and verified 2026-10-04: read-only provenance audit established that initial reachable commit `9c15cb1c976041229f78ef4548588618ac983a0e` contains `soc-project-skeleton-v10.3.zip`, representative base files, the required forensic scaffold, and TODO-marker history; annotated tag `v10.3-phase-00` was examined without mutation. Later commits `14f9620abbde0d555305705833fae1574199e8e0` and `abbc7a233c61c0cecb309c8c6fdb9e8727cbc9c5` respectively added then deleted unrelated tracked path `saleem`; no Git initialization, duplicate/empty commit, history rewrite, tag mutation, or skeleton modification is justified. |
| P01-003 | Confirm required base layout: `contracts/`, `move/`, `test/`, `scripts/`, `src/`, `config/`, `dashboard/`, `docs/`, `.gitlab/`. | ✅ | Audit complete 2026-10-04: `contracts/`, `test/`, `scripts/`, `src/`, `config/`, `dashboard/`, and `docs/` verified in worktree and initial baseline `9c15cb1c976041229f78ef4548588618ac983a0e`; worktree-only `move/` scaffold contains empty `move/modules/` and `move/packages/` with no tracked files at baseline or `HEAD`. Literal `.gitlab/` is absent from worktree and baseline; tracked root `.gitlab-ci.yml` exists at `HEAD` but was introduced after baseline. Bounded layout-contract/documentation gap recorded; no layout, Git-history, tag, remote, or skeleton mutation is justified. |
| P01-004 | Add `src/forensics/`, `test/forensics/`, `config/opa/`, `src/mcp_middleware/forensic_tools.py`, and `docs/forensic-report-template.md`. | ✅ Complete and verified 2026-10-04 | Read-only audit verified all required paths in baseline `9c15cb1c976041229f78ef4548588618ac983a0e` with identical tree/blob identities at `HEAD` `b066b41d1ef8b598724c53a38234788da01812e2`; required TODO markers present; no forensic change justified. |
| P01-005 | Add `# TODO(phase-10)` to each newly created forensic file. | ✅ Complete and verified 2026-10-04 | Read-only verification at `ceacc1289322241de4c54bbfa9f0339b2558aa3e` confirmed 17/17 required human-readable forensic files already contain specific `TODO(phase-10...)` markers; no marker, code, test, policy, template, middleware, or cache change was justified. |
| P01-006 | Start the skeleton Docker Compose stack and verify the Redis stub starts cleanly. | ✅ Complete and verified 2026-10-05 | Existing `redis:7` Compose stub validated: `compose-up-exit=0`, `redis-cli ping` returned `PONG` on attempt 1, logs reported `Ready to accept connections tcp`, and `compose-down-exit=0` removed the project container/network; no repository files changed and `docs/.backup/` remained untracked. |
| P01-007 | Run `npm install` and `pip install -r requirements.txt` without errors. | ✅ Complete and verified 2026-10-05 | `npm install` and `npm ls --depth=0` succeeded without manifest/lockfile changes; Kali PEP 668 safely blocked system pip, then ignored project-local `.venv/` installed `requests 2.34.2` and `langgraph 1.2.12` with successful imports; `package.json`, `package-lock.json`, and `requirements.txt` SHA-256 identities were unchanged. |
| P01-008 | Push to private GitLab and verify the placeholder `.gitlab-ci.yml` pipeline is green. | ✅ | Complete and verified 2026-10-05: existing private GitLab publication was verified for `0e070d56caa7e2b0842cd422552574a91c9136e2`; GitLab UI showed the placeholder pipeline passed/green (pipeline ID/URL not captured); `HEAD == main == gitlab/main == origin/main == 0e070d56caa7e2b0842cd422552574a91c9136e2`. No CI, remote, dependency, or application change was made. |
| P01-009 | Read and map every `TODO(phase-N)` marker to the relevant future phase. | ✅ | Complete and verified 2026-10-05: tracked marker inventory was mapped to the checklist phases at `91476785ac05621e0256edad38263168b20ca8a8`; cross-phase markers were retained as intentional dependencies; no TODO marker, source, CI, dependency, or configuration file was changed. |



### P01-009 — TODO marker inventory and future-phase mapping

- **Status:** ✅ Complete and verified 2026-10-05.
- **Scope completed:** Read-only inventory and mapping of every tracked `TODO(phase-N)` marker to the corresponding implementation phase in this checklist.
- **Evidence baseline:** `HEAD == main == gitlab/main == origin/main == 91476785ac05621e0256edad38263168b20ca8a8` before the inventory. The final repository boundary showed only `?? docs/.backup/`.
- **Mapping result:** Markers map coherently to Phase 1 (skeleton/deployment target), Phase 2 (manifest ingestion), Phase 3 (DevSecOps scanning and fixtures), Phase 4 (storage/MCP), Phase 5 (LLM transport and agents), Phase 6 (consensus), Phase 8 (observability/RASP), Phase 9 (mitigation/egress/OPA), Phase 10 (forensics/evidence integrity and related benchmark/dashboard/paper scaffolding), Phase 11 (consensus attack detection), Phase 12 (wallet/key security), Phase 13 (compliance), and Phase 14 (executive reporting).
- **Cross-phase markers retained:** `phase-1/7` hardened deployment target; `phase-3, activated in phase-11` DeFi detector interface/activation dependency; `phase-4/6` Anvil-sandbox middleware/reproduction dependency; and `phase-10c/10d` on-chain-forensics collection/tooling sub-workstreams.
- **Files changed:** No TODO-bearing implementation, configuration, CI, dependency, test, policy, template, or runtime file changed. This documentation closeout changes only `docs/CHECKLIST.md` and `docs/HANDOFF.md`.
- **Validation evidence:** Read-only tracked-file `git grep` inventory, phase-count summary, checklist phase-section review, and final Git boundary check. The raw scan included documentation references to TODO markers; the detailed per-file inventory and mapping, rather than aggregate counts alone, is authoritative.
- **Security checks:** `docs/.backup/` remained untracked and was not inspected or staged. No evidence-vault material, raw evidence, credentials, keys, tokens, certificates, remotes, Git history, tags, CI configuration, or host shell configuration was accessed or changed.
- **Dependencies and limitations:** P01-009 records planned implementation ownership; it does not implement, remove, rename, or validate the TODO work. The user-local prompt warning after the completed scan did not alter repository state and is outside P01-009 scope.
- **Runbook impact:** No update required; this project-specific documentation inventory does not add a reusable operator procedure.
- **Next recommended task:** P01-GATE — Reconcile the Phase 1 completion gate against the completed P01-001 through P01-009 evidence.


### P01-008 — Private GitLab publication and placeholder-pipeline verification

- **Status:** ✅ Complete and verified 2026-10-05.
- **Scope completed:** Verified the existing private GitLab publication and the existing tracked root placeholder `.gitlab-ci.yml` pipeline for the completed P01-007 dependency-installation closeout commit.
- **Files changed:** No implementation, CI, dependency, remote, or application files changed during verification. This documentation closeout changes only `docs/CHECKLIST.md` and `docs/HANDOFF.md`.
- **Validation evidence:** Read-only repository and remote-ref inspection confirmed `HEAD`, `main`, `gitlab/main`, and `origin/main` each resolved to `0e070d56caa7e2b0842cd422552574a91c9136e2`. The tracked root `.gitlab-ci.yml` remained present and unchanged by the P01-007 commit. GitLab UI observation showed the placeholder pipeline completed with green/passed status.
- **Evidence reference:** Sanitized P01-008 terminal evidence and GitLab UI observation in the implementation thread. Pipeline identifier and job URL were not captured.
- **Security checks:** `docs/.backup/` remained intentionally untracked and was neither inspected nor staged. No credentials, tokens, private keys, evidence-vault material, raw evidence, CI variables, remote settings, Git history, tags, or shell configuration were accessed or changed.
- **Dependencies and limitations:** The existing GitLab-first publication workflow and placeholder CI configuration were preserved. No CI redesign, dependency upgrade, Docker Compose action, package operation, application implementation, cache cleanup, or P01-009 work was performed.
- **Runbook impact:** No update required; the existing GitLab-first publication, CI-result review, GitHub publication, and three-way synchronization procedure already applies.
- **Next recommended task:** P01-009 — Read and map every `TODO(phase-N)` marker to the relevant future phase.


### P01-001 — Skeleton reconciliation audit

- **Status:** ✅ Complete and verified.
- **Scope completed:** Completed a controlled read-only reconciliation of the existing tracked repository skeleton against `soc-project-skeleton-v10.3.zip`. No archive extraction or overwrite occurred.
- **Scope not completed:** No source, configuration, dependency, CI, Docker Compose, test, cache-cleanup, or application implementation work. P01-002 through P01-009 were not started.
- **Archive evidence:** `soc-project-skeleton-v10.3.zip` SHA-256: `ba7b16c8ccc792079dd8592a4af6617ac210bd8ea97523d7418dde9ed41859b4`. The archive is rootless and maps directly to repository-root paths. It contains 160 file members; all 160 are tracked in Git.
- **Layout evidence:** Verified required base roots: `contracts/`, `move/`, `test/`, `scripts/`, `src/`, `config/`, `dashboard/`, and `docs/`. Verified `move/`, `move/modules/`, and `move/packages/` as present intentionally empty filesystem scaffold directories. Verified `src/forensics/`, `test/forensics/`, `config/opa/`, `src/mcp_middleware/forensic_tools.py`, and `docs/forensic-report-template.md`.
- **Metadata and TODO evidence:** `.gitignore`, `.gitlab-ci.yml`, `docker-compose.yml`, `package.json`, and `requirements.txt` were present and tracked. `TODO(phase-N)` markers were inventoried across tracked decodable scaffold text files. Docker Compose, dependency installation, and CI execution were intentionally not performed because they belong to P01-006 through P01-008.
- **Tracked-artifact observations:** The ZIP baseline and Git index contain 65 tracked Python generated-cache paths, while `.gitignore` ignores future `__pycache__/` and `*.py[cod]` artifacts. The tracked non-archive file `e version` is an ANSI-formatted historical Docker service-status capture. Both observations are deferred to separately scoped cleanup/hygiene work and were not modified.
- **Validation commands actually run:** Read-only Git status/index comparisons; ZIP SHA-256/listing; non-extracting ZIP membership comparison; bounded metadata/TODO inventory; tracked-layout check; Move filesystem-metadata check; final `git status --short`, `git --no-pager diff --stat`, and `git --no-pager diff --cached --stat`; GitLab CI passed; GitHub publication; and fetched three-way SHA verification.
- **Factual result:** Final pre-documentation boundary check showed only `?? docs/.backup/`; tracked and staged diff summaries were empty. Evidence commit `c6d5017d44eaa2c12f5b2520a6d9d5fe49cfce7e` passed GitLab CI (green observed; pipeline ID/URL not captured), was published to GitHub, and fetched verification proved `main == gitlab/main == origin/main == c6d5017d44eaa2c12f5b2520a6d9d5fe49cfce7e`.
- **Files changed:** The technical audit changed no files. Documentation/evidence commit `c6d5017d44eaa2c12f5b2520a6d9d5fe49cfce7e` changed `docs/CHECKLIST.md` and `docs/HANDOFF.md`.
- **Security checks:** No archive extraction, parent-archive access, Docker startup, dependency installation, test/scanner execution, secret/evidence-vault access, key handling, CI configuration change, remote configuration, or force push occurred. `docs/.backup/` remains intentionally untracked.
- **Dependencies and limitations:** The interactive shell/PATH and prompt integration issue was repaired separately as user-local Zsh maintenance outside the repository. P01-001 does not authorize cache cleanup or Move-package initialization.
- **Runbook impact:** Not required; no reusable operational procedure was created or changed.
- **Git commit and publication:** Evidence commit `c6d5017d44eaa2c12f5b2520a6d9d5fe49cfce7e` — `docs(phase-01): record P01-001 skeleton reconciliation`; published to GitLab `main`, GitLab CI passed (pipeline ID/URL not captured), published to GitHub `origin/main`, and fetched three-way synchronization was verified.
- **Next recommended task:** P01-002 — Initialize Git and commit the full skeleton with every TODO stub.

## P01-GATE — Phase 1 completion gate

- [x] Skeleton pipeline is green in GitLab. Verified by green GitLab pipelines for P01-008 and P01-009 documentation closeouts; most recent verified pre-gate evidence commit `96751fc5eff2fa523ce3c2bf3b69199d853a5086`.
- [x] Repository tree matches the expected base and forensic layout. Required tracked roots and forensic paths were verified. Documented caveat: literal `.gitlab/` is absent while root `.gitlab-ci.yml` is tracked; `move/` is a worktree-only empty scaffold because Git does not preserve empty directories.
- [x] TODO markers are accounted for. P01-009 mapped every tracked `TODO(phase-N)` marker to its future implementation phase and retained explicit cross-phase dependencies.
- [x] Baseline skeleton commit/tag exists. Initial reachable skeleton baseline commit is `9c15cb1c976041229f78ef4548588618ac983a0e`. Existing annotated Phase 0 tag `v10.3-phase-00` resolves to `68f97d8d63f859969fc2762f7a30ea653791e44e`; the tag and baseline commit are distinct provenance anchors.
- [x] `docs/HANDOFF.md` is updated for Phase 2. This P01-GATE closeout advances the current phase to Phase 2 and identifies P02-001 as the next task.

**Gate status:** ✅ Complete and verified 2026-10-05

**Pre-closeout evidence baseline:** `96751fc5eff2fa523ce3c2bf3b69199d853a5086`. The gate-close documentation commit will record this reconciliation after its own GitLab-CI and publication lifecycle.

**Known limitations:** The documented literal-`.gitlab/` and empty-Move-directory layout gaps remain bounded baseline/task-specification facts. No layout, CI, Git-history, tag, remote, cache, or skeleton change is authorized by this gate.

---

# Phase 2 — Zone 1: Manifest-driven ingestion gateway

**Goal:** Validate target-project topology, dependency/toolchain hashes, and verified repository asset paths.

| ID | Task | Status | Evidence / commit |
|---|---|---|---|
| P02-001 | Configure sample `foundry.toml`, `hardhat.config.js`, and `Move.toml` values. | ✅ | Complete and verified 2026-10-05: implementation/evidence commit `e61ee99e5912de6748114eb7d960d465a96d18ff` passed reported green GitLab CI, was published to GitHub, and fetched verification proved `main == gitlab/main == origin/main == e61ee99e5912de6748114eb7d960d465a96d18ff`. |
| P02-002 | Add a deliberately flawed sample contract under `contracts/solidity/`. | 🟡 | Implemented and locally structurally validated 2026-10-05: `contracts/solidity/VulnerableVault.sol` intentionally performs an external ETH call before balance accounting; commit and publication lifecycle pending. |
| P02-003 | Implement `scripts/ingest-manifests.mts` schema parsing and validation for Foundry, Hardhat, and Move manifests. | ⬜ | — |
| P02-004 | Implement dependency and compiler-toolchain hash verification. | ⬜ | — |
| P02-005 | Emit verified repository asset-map JSON for contracts, Move modules/packages, and test layouts. | ⬜ | — |
| P02-006 | Add the ingestion job to `.gitlab-ci.yml`. | ⬜ | — |
| P02-007 | Replace the Hardhat placeholder with an ingestion smoke test. | ⬜ | — |
| P02-008 | Verify Developer Push, webhook, and on-chain-event stub all reach the pipeline entry. | ⬜ | — |


### P02-001 — Sample Foundry, Hardhat, and Move configuration

- **Status:** ✅ Complete and verified 2026-10-05. Implementation/evidence commit `e61ee99e5912de6748114eb7d960d465a96d18ff` passed reported green GitLab CI, was published to GitHub, and fetched verification proved `main == gitlab/main == origin/main == e61ee99e5912de6748114eb7d960d465a96d18ff`.
- **Scope completed:** Replaced Phase 2 placeholders with local sample configuration for Foundry, Hardhat, and Move.
- **Files changed:** `config/foundry.toml`, `config/hardhat.config.js`, and `config/Move.toml`; this closeout also changes `docs/CHECKLIST.md` and `docs/HANDOFF.md`.
- **Configuration result:** Foundry uses `contracts/solidity`, `test/foundry`, `out`, `lib`, and Solidity `0.8.24`. Hardhat uses Solidity `0.8.24`, optimizer disabled with `runs: 200`, repository-local source/test/cache/artifact paths, and no `networks` object. Move defines package `MoveTargetPackage` version `0.0.1`, local placeholder address `blockchain_soc = "0x0"`, and empty dependencies.
- **Validation commands and factual results:** `forge config --root . --config-path config/foundry.toml` resolved the configured paths, compiler, and disabled optimizer. Node structural validation loaded `config/hardhat.config.js` and verified compiler/settings/paths with no networks configuration. `npx --no-install hardhat --version` returned `2.29.1`. Python `tomllib` structural validation passed for `config/Move.toml`.
- **File identity evidence:** SHA-256 `config/foundry.toml` `71c0b047c483a4e0c5aca70b5bc0315a75d2b3d73edd8c86e7c944a2bcb358bf`; `config/hardhat.config.js` `9f210a2ce515df82925e28642dfac959cc3f99b7ced3c3a2a23e6fd65f6a62b5`; `config/Move.toml` `52211ca389cb1353cd04c32ba21b2052e62fec320f7de8e4b759ddb4f6671f71`.
- **Scope not completed:** No Solidity contract compilation, Hardhat test execution, Move package initialization/build, Anvil/Docker/service startup, network/RPC access, package installation, dependency/lockfile change, CI modification, or P02-002 work.
- **Security checks:** No accounts, private keys, tokens, RPC URLs, network definitions, credentials, evidence-vault material, raw evidence, or secret-bearing configuration was added. `docs/.backup/` remained untracked and was not inspected or staged.
- **Dependencies and limitations:** Foundry `1.8.3`, Hardhat `2.29.1`, Node `v24.19.0`, and npm `12.0.2` were available. Move validation was TOML structural validation only; no Move toolchain was asserted or used.
- **Runbook impact:** Not required. This is a project-specific sample configuration and has not established a new reusable operator procedure.
- **Next recommended task after P02-001 publication:** P02-002 — Add a deliberately flawed sample contract under `contracts/solidity/`.

### P02-002 — Deliberately flawed Solidity reentrancy fixture

- **Status:** 🟡 Implemented and locally structurally validated 2026-10-05; compiler/test execution, implementation/documentation commit, and publication lifecycle pending.
- **Scope completed:** Added exactly one intentionally vulnerable local coursework fixture: `contracts/solidity/VulnerableVault.sol`.
- **Vulnerability pattern:** `withdraw(uint256 amount)` checks the ledger balance, performs `msg.sender.call{value: amount}("")`, then decrements `balances[msg.sender]`. The external interaction therefore precedes effects and deliberately exposes a reentrancy condition.
- **Safety boundary:** The source declares itself an intentionally vulnerable local coursework fixture that must never be deployed or funded. It contains no network configuration, RPC URL, address, account, key, token, credential, or deployment instruction.
- **Validation commands and factual results:** Python structural validation confirmed SPDX MIT, exact Solidity `0.8.24` pragma, local-only safety notice, balance ledger, external call, and post-call balance update. The validation confirmed the external call appears before balance decrement and found no URL, RPC, private-key, mnemonic, API-key, or address-like content.
- **File identity evidence:** SHA-256 `contracts/solidity/VulnerableVault.sol` `31a68c972361a3e537cd9b6107eb4efb7f47b77236958098db61dbefa184354a`.
- **Scope not completed:** No compiler build, Foundry/Hardhat test, attacker or exploit fixture, scanner/formal-verification execution, service startup, Anvil/Docker startup, deployment, funding, RPC access, account/wallet/key use, dependency change, CI change, or P02-003 work occurred.
- **Runbook impact:** Not required. This intentionally unsafe coursework fixture is not a verified user-operational procedure.
- **Next recommended task after P02-002 publication:** P02-003 — Implement `scripts/ingest-manifests.mts` schema parsing and validation for Foundry, Hardhat, and Move manifests.

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
