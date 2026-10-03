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
| Current task | P00-015 — Create an operator signing key for evidence-manifest signing |
| Current thread | P00-014 evidence-vault service-account isolation and validation is complete and verified at `54bde63816abe2f7015b20c87dfc50adcbd98a13`; P00-015 signing-key planning and baseline discovery is next. |
| Current branch | `main` |
| Last verified commit | `54bde63816abe2f7015b20c87dfc50adcbd98a13` — `docs(phase-00): record P00-014 evidence vault validation` |
| Last GitLab pipeline | Passed for `54bde63816abe2f7015b20c87dfc50adcbd98a13` (pipeline identifier not captured) |
| Last GitHub post | Posted — `origin/main` resolved to `54bde63816abe2f7015b20c87dfc50adcbd98a13` |
| Synchronization | Verified — `main == gitlab/main == origin/main == 54bde63816abe2f7015b20c87dfc50adcbd98a13` |
| Last updated | 2026-10-03 |

## Completed since previous handoff

- **P00-012 — DFIR tooling baseline:** ✅ Complete and verified.
  - Safely version/help validated the required Kali DFIR baseline: Sleuth Kit 4.14.0; optional Autopsy 2.24-6kali1; Volatility 3 2.28.2 via pipx as `vol`; Plaso 20260119-1kali1 using packaged `plaso-*` utilities; dc3dd 7.3.1-4; ewf-tools 20140816-2+b2; YARA 4.5.8; tshark 4.6.6; tcpdump 4.99.6; GnuPG 2.4.9; and minisign CLI 0.12 from package 0.12-1+b1. Minisign was the sole package newly installed in the final reviewed transaction; GnuPG was already present and only safely validated.
  - Minisign’s reviewed transaction installed exactly one new package: `0 upgraded, 1 newly installed, 0 to remove and 0 not upgraded`. `dpkg-query` reported `install ok installed`; `minisign -v` returned `minisign 0.12`; bare invocation printed usage only. `dpkg --audit` returned no findings and `apt-mark showhold` returned no held packages.
  - Optional Zeek was not installed because the available Kali package required `libc6 < 2.38`, conflicting with installed `libc6 2.43-4`. No forced installation, system downgrade, alternate repository, or workaround was attempted.
  - No disk, memory, packet, or live-evidence acquisition occurred. No packet capture, network analysis, Autopsy launch, signing-key generation/import/export/use, signature creation/verification, or `apt autoremove` occurred. No secret, private key, credential, raw evidence, or sensitive case material was displayed or committed.
  - Repository boundary after validation: only `docs/.backup/` remained untracked before documentation edits. Package and pipx state are host-local, not repository artifacts.
  - Documentation closeout commit `3fa2735ee251f90a4dc46619e6bf85ebae0371c6` passed GitLab CI (green observed; pipeline identifier not captured), was posted to GitHub, and final verification proved `main == gitlab/main == origin/main == 3fa2735ee251f90a4dc46619e6bf85ebae0371c6`.

- **P00-007:** ✅ Complete and verified.
- A private coursework CA, Windows proxy server certificate, and Kali client certificate were created in protected host-local storage outside Git.
- Kali CA self-verification, client certificate chain/client-purpose validation, and client private-key/certificate matching succeeded.
- The Windows server certificate chained to the private CA for server purpose, contained the approved private-interface IP in its subject alternative name, and matched its private key.
- Kali time synchronization was restored and verified active before final certificate checks.
- The Windows-local Caddy configuration requires and verifies client certificates against the private CA, uses the private-CA-issued server certificate/key, disables the Caddy administration API and automatic HTTPS, and reverse-proxies only to the loopback backend.
- Caddy static validation returned `Valid configuration`; Caddy recognized the TLS client-authentication policy. No Caddy/Ollama process was started and no listener, live mTLS handshake, bearer-token request, or Kali-to-Windows inference request was made.
- Files changed: `docs/CHECKLIST.md`, `docs/HANDOFF.md`, and `docs/RUNBOOK.md`. Host-local PKI and Caddy configuration remain outside Git.
- Documentation/evidence commit: `3eb7d51225622833d7813d64bb9dd343ad8e3f62`; GitLab Pipeline #23 passed; the same commit was posted to GitHub; `main == gitlab/main == origin/main == 3eb7d51225622833d7813d64bb9dd343ad8e3f62`.
- Security boundary: no private key, certificate body, password, token, or other secret-bearing output is recorded in tracked documentation. The CA private key is not referenced by Caddy.
- Post-verification maintenance: the Windows-local Caddyfile was migrated from deprecated `trusted_ca_cert_file` to `trust_pool file`, formatted, and validated with exit code `0`; a timestamped host-local backup matched the live Caddyfile SHA-256. Caddy and Ollama remained stopped with no listeners on ports `11434` or `11435`.
- Historical documentation-maintenance note: the P00-007 trust-pool formatting change was validated before later P00-008/P00-009 work. P00-008/P00-009 evidence was subsequently recorded in commit `e9c788688ae2cd18187eb5710d22837e0aaf3d9f`, which passed GitLab CI, was posted to GitHub, and was verified synchronized. The host-local Caddyfile remains user-readable, so it must not contain a plaintext Bearer token.

- **P00-010 — Private GitLab remote and GitLab CI/CD source-of-truth audit:** ✅ Complete and verified.
  - Existing GitLab fetch/push remote verified as `gitlab-soc:root/blockchain-security-project-remastered.git`; existing GitHub fetch/push remote verified as `git@github.com:ali4210/Blockchain-Security-Project-Remastered.git`.
  - Read-only ref audit verified `main == gitlab/main == origin/main == 1c1144be9a35423f41c5c4a8962751fe6a9299a9`; `git ls-remote --heads gitlab main` returned that SHA for `refs/heads/main`.
  - Tracked root `.gitlab-ci.yml` was inspected: one `verify` stage and `runner_smoke_test`, using existing `soc-docker` runner tag, checking repository/control files, and emitting CI metadata. No tracked CI include references were found.
  - No GitLab project, remote, runner, token, CI/CD variable, visibility setting, branch protection, pipeline definition, or CI configuration was created, changed, or deleted. No secret-bearing value was exposed.
  - Evidence commit `e735198dcf25d186d659313520976d342d973380` — `docs(phase-00): record GitLab CI source-of-truth audit` — passed GitLab CI, was posted to GitHub, and final fetched verification proved `main == gitlab/main == origin/main == e735198dcf25d186d659313520976d342d973380`.
  - `docs/RUNBOOK.md` update was not required because no user-executable operational procedure changed. Pipeline identifier and job URL were not captured.

- **P00-011 — GitHub account/public-mirror policy:** ✅ Complete and verified.
  - Read-only audit confirmed GitLab remote `gitlab-soc:root/blockchain-security-project-remastered.git` remains the private CI/CD source of truth and GitHub remote `git@github.com:ali4210/Blockchain-Security-Project-Remastered.git` remains a manually synchronized secondary remote.
  - Audit evidence at `b634e287f140b64ffac03d2b58f1f19aee7bc6d8` confirmed `main == gitlab/main == origin/main`; GitHub advertised `refs/heads/main` at the same SHA.
  - No `.github/workflows/` directory, tracked GitHub automation reference, or local mirror/push-routing override was found. Read-only GitHub metadata observed only `main`, with no releases and no tags.
  - No automatic public mirroring was configured or authorized; no external infrastructure was changed.
  - Documentation closeout commit `e01d36a5de7a61bf4821b4895ecb35f149a1ba38` passed GitLab CI, was posted to GitHub, and fetched verification proved `main == gitlab/main == origin/main == e01d36a5de7a61bf4821b4895ecb35f149a1ba38`.
  - Limitation: GitHub repository visibility, website-side secrets, webhooks, and repository/account settings were intentionally not inspected or modified; their absence is not claimed.
  - `docs/RUNBOOK.md` was not updated because no verified user-executable operational procedure changed.

## Project purpose

Build the Enterprise V10.3 Autonomous AI-Native Blockchain Security Operations Center as a phased, security-first coursework/portfolio system. The system combines manifest-driven smart-contract ingestion, DevSecOps security gates, sanitized AI-assisted analysis, an MCP tool layer, local-model orchestration, independent PoC consensus, monitored deployment/abort behavior, DFIR evidence integrity, consensus monitoring, wallet-security controls, compliance automation, and a sanitized executive HTML report.

## Current implementation status

- **P00-001 — Kali Linux update and baseline verification:** ✅ Complete and verified.
  - Package-management checks passed; reboot was not required; Kali Rolling 2026.3 and kernel `7.1.5+kali-amd64` were recorded.
  - P00-001 final ledger commit synchronized at `833baea13e275066ed995c51429c43e02d0229cd`.
  - Runbook/governance documentation commit synchronized at `1e8620d9ad46d15d9ff47b2c33d1cd0fd5663dcb`.
- **P00-002 — Core Kali development prerequisites:** ✅ Complete and verified.
  - Verified Git `2.53.0`, Node.js `v24.19.0`, npm `12.0.2`, Python `3.14.7`, pip `26.1.2`, Docker Engine `29.8.1`, Docker Compose `v5.5.1`, active Docker service, and current-user Docker access.
  - Documentation/evidence commit `bd7d284c50debf43330504721dea77bb8252d804` was pushed to GitLab and GitHub; GitLab Pipeline #12 passed; `main == gitlab/main == origin/main == bd7d284c50debf43330504721dea77bb8252d804`.
- **P00-003 — Foundry and Hardhat prerequisites:** ✅ Complete and verified.
  - Verified Foundry `forge`, `anvil`, and `cast` at `1.8.3`; a disposable local Foundry smoke project initialized and built successfully with Solc `0.8.37`; Cast conversion returned `1000000000000000000`; the disposable workspace was removed.
  - Verified project-local Hardhat `2.29.1`; `package-lock.json` version 3 records root range `^2.22.0`, resolved Hardhat `2.29.1`, TypeScript `5.9.3`, and tsx `4.23.15`.
  - Commit `473793554ceb7898b4b2165dfef401c47fa14d50` was pushed to GitLab; GitLab Pipeline #13 passed; the same commit was posted to GitHub; `main == gitlab/main == origin/main == 473793554ceb7898b4b2165dfef401c47fa14d50`.
- **P00-004 — Smart-contract security tooling prerequisites:** ✅ Complete and verified.
  - Slither `0.11.6` and Certora CLI `8.19.2` were installed through isolated pipx environments; `slither --version`, `certoraRun --version`, and Certora local help succeeded.
  - Mythril `v0.24.8` was validated from `mythril/myth:latest` digest `sha256:49e11758e359d0b410f648df5bbcba28a52e091a78e4772b5c02b9043666b4ff` in a hardened no-network, read-only container with tmpfs-only writable paths, dropped capabilities, and no-new-privileges. No source, bytecode, RPC target, contract scan, symbolic analysis, or formal proof was run.
  - `CERTORAKEY_STATUS=not_set`; no key was requested, printed, persisted, or committed. Full Certora proof execution remains intentionally deferred until an authorized operator manages a personal access key outside Git, project files, and captured output.
  - Documentation commit `3a3e2f936200e5324165304b7ac5ffbb3b6f31ba` was posted to GitLab; GitLab Pipeline #15 passed. The same commit was posted to GitHub; `main == gitlab/main == origin/main == 3a3e2f936200e5324165304b7ac5ffbb3b6f31ba`.
- **P00-005 — Ollama local-model prerequisite:** ✅ Complete and verified.
  - Ollama `0.34.4` was already installed; five initial local model tags and factual metadata were inspected before any model-state change.
  - With explicit approval, redundant `deepseek-r1:32b` was removed; post-removal validation retained `deepseek-r1:32b-stable`.
  - Final approved local set: `qwen2.5-coder:32b`, `deepseek-r1:32b-stable`, `qwen3.5:9b`, and `qwen3:32b`.
  - Documentation/evidence commit `afb049f37ad850f67c3dbc534a892b69634f5a1c` passed GitLab Pipeline #18 and was synchronized to GitHub.
  - Final verification commit `7a82193af9a3d5aa8397d6f9b6c49018f04f1fc6` passed GitLab Pipeline #19; `main == gitlab/main == origin/main == 7a82193af9a3d5aa8397d6f9b6c49018f04f1fc6`.
- **P00-006 — Ollama loopback binding and private-interface reverse proxy:** ✅ Complete and verified.
  - Ollama was validated as a normal-user foreground process bound solely to `127.0.0.1:11435`; direct `/api/tags` health returned four models.
  - Caddy 2.11.4 was validated as a normal-user foreground reverse proxy with its administration endpoint disabled and its sole listener at `192.168.0.189:11434`; the proxy forwarded to `127.0.0.1:11435`, and proxied `/api/tags` returned four models.
  - Docker/Open WebUI, Windows Firewall changes, mTLS material, bearer authorization, and Kali-to-Windows testing were not performed; the validated services are non-persistent foreground processes.
  - Documentation/evidence commit `f9856ed4c181cb6740e7f26043e96a54d3ec0853` passed GitLab Pipeline #20 and was synchronized to GitHub; `main == gitlab/main == origin/main == f9856ed4c181cb6740e7f26043e96a54d3ec0853`.
- **P00-007 — Private PKI and Caddy mTLS static validation:** ✅ Complete and verified.
  - Private CA, Windows server certificate, and Kali client certificate were created in host-local protected storage outside Git; local certificate chain/purpose, identity, permissions/ACLs, and key/certificate matching checks succeeded.
  - Caddy mTLS configuration requires and verifies a client certificate against the private CA, uses the private-CA-issued server certificate/key, and forwards only to the loopback backend.
  - Static Caddy validation returned `Valid configuration`; no Caddy/Ollama service start, listener, live mTLS request, bearer authorization, or cross-host inference occurred.
  - Documentation/evidence commit `3eb7d51225622833d7813d64bb9dd343ad8e3f62` passed GitLab Pipeline #23; final-status commit `44c50e1cdd840aa2920dd55ef5fe9eebedd82966` passed GitLab Pipeline #24; both commits were posted to GitHub and final synchronization verified `main == gitlab/main == origin/main == 44c50e1cdd840aa2920dd55ef5fe9eebedd82966`.
- **P00-008 — Bearer authorization and backend/verifier isolation:** ✅ Complete and verified.
  - During the approved temporary test, the bearer verifier listened only on `127.0.0.1:11436`, Ollama listened only on `127.0.0.1:11435`, and direct Kali access to either backend port timed out.
  - Valid mTLS without a Bearer credential returned HTTP `401`; no secret value was committed or documented.
- **P00-009 — Authenticated Kali-to-Windows mTLS/Bearer transport-path validation:** ✅ Complete and verified.
  - No client certificate was rejected during the TLS handshake; valid mTLS with the configured Bearer credential caused the verifier to record an allow decision.
  - The root route returned HTTP `403` after authorization, recorded as a route/backend response rather than token rejection; an authenticated `/api/tags` response remains an optional separately approved functional follow-up.
  - P00-008/P00-009 documentation commit `e9c788688ae2cd18187eb5710d22837e0aaf3d9f` passed GitLab CI, was posted to GitHub, and was verified synchronized across `main`, `gitlab/main`, and `origin/main`.
  - Temporary Caddy, verifier, and Ollama test processes were stopped and their temporary listeners released.
- Phase 0 remains active and its completion gate is not ready.

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

## Completed task record — P00-007

### P00-007 — Generate private CA, server certificate, and client certificate for Kali-to-Windows mTLS

**Objective**

Generate and protect a private coursework CA, issue a Windows proxy server certificate and a Kali client certificate, configure Caddy to require mTLS only after the certificate material is available, and validate the local certificate/configuration state without bearer authorization or a Kali-to-Windows authenticated inference request.

**Status**

✅ Complete and verified on 2026-10-01. Local certificate and configuration validation succeeded; documentation/evidence commit `3eb7d51225622833d7813d64bb9dd343ad8e3f62` passed GitLab Pipeline #23; final-status commit `44c50e1cdd840aa2920dd55ef5fe9eebedd82966` passed GitLab Pipeline #24; both commits were posted to GitHub, and `main == gitlab/main == origin/main == 44c50e1cdd840aa2920dd55ef5fe9eebedd82966`.

**Scope**

- Create a private CA and issue server/client certificates only in approved host-local secret locations.
- Prepare Caddy mTLS configuration without committing private keys, certificate contents, passwords, or tokens.
- Verify certificate/key permissions and local configuration with sanitized output.
- Record factual results and the verified procedure only after execution.

**Explicitly out of scope**

- Bearer-token authorization, which belongs to P00-008.
- Kali-to-Windows authenticated inference, which belongs to P00-009.
- Docker/Open WebUI startup or reconfiguration.
- Windows Firewall changes, internet exposure, and any direct Ollama LAN listener.
- Committing CA keys, server/client private keys, passwords, tokens, certificate contents, or raw secret-bearing output.

**Expected tracked files**

- `docs/CHECKLIST.md`
- `docs/HANDOFF.md`
- `docs/RUNBOOK.md`
- Approved non-secret configuration references only, if a repository configuration reference becomes necessary.

Private certificate material remains host-local and outside Git. `docs/.backup/` remains untracked local recovery material and must not be staged or committed.

**Acceptance criteria**

- [x] A private CA, Windows proxy server certificate, and Kali client certificate exist only in approved host-local secret locations.
- [x] Caddy is configured to require a trusted client certificate without committing secret material.
- [x] Certificate/key permissions and local configuration validation are recorded without revealing private material.
- [x] P00-008 bearer authorization and P00-009 authenticated Kali-to-Windows transport-path validation were completed on 2026-10-02; see the completion addendum below. A successful authenticated Ollama API response remains an optional separately approved functional follow-up.

**Validation approach**

Exact commands must be selected only after identifying the actual certificate tooling available on the authorized Windows and Kali hosts. Before any credential-generation action, inspect the installed toolchain and approved host-local storage locations. Do not document unexecuted commands as verified.

**Dependencies**

- P00-006 loopback/private-interface proxy separation is complete and verified.
- The authorized Windows inference host and Kali VM remain available.
- Certificate tooling and safe host-local secret-storage locations must be identified before generation.

**Security constraints**

- Never paste, print, store, or commit CA private keys, server/client private keys, passwords, tokens, certificate contents, or secret-bearing command output.
- Do not remove the P00-006 binding separation: Ollama remains loopback-only and Caddy remains the sole private-interface listener.
- Do not begin bearer authorization or Kali-to-Windows authenticated inference validation in P00-007.
- Do not use force-push.

## P00-008/P00-009 completion addendum — 2026-10-02

- **Validated enforcement:** Caddy configuration validation passed with strict SNI/Host enforcement enabled for mandatory TLS client authentication. The server certificate was reissued under the existing private CA with `DNS:ollama-mtls.home.arpa` and `IP:192.168.0.189` SANs, and its key match and CA chain were verified.
- **Validated isolation:** During the approved temporary test, Ollama listened only on `127.0.0.1:11435` and the forward-auth verifier only on `127.0.0.1:11436`. Kali reached the Caddy gateway but direct Kali connections to ports `11435` and `11436` timed out.
- **Validated request path:** No client certificate caused a TLS certificate-required alert with no HTTP response. Valid mTLS without Bearer returned HTTP `401`. Valid mTLS with the configured Bearer caused the verifier to record `decision=allow`; the subsequent `GET /` response was HTTP `403`, recorded as a route/backend response after authorization rather than a credential failure.
- **Runtime status:** Temporary Caddy, verifier, and Ollama processes were stopped after testing; the test ports were confirmed released. The token was not documented or committed, and the temporary Windows clipboard transfer was overwritten and verification-confirmed.
- **Documentation closeout:** Commit `e9c788688ae2cd18187eb5710d22837e0aaf3d9f` recorded the P00-008/P00-009 validation, passed GitLab CI, was posted to GitHub, and was verified synchronized across `main`, `gitlab/main`, and `origin/main`.
- **Optional follow-up:** If application-level API success evidence is later required, perform one separately approved temporary `GET /api/tags` request through the same mTLS and Bearer path, then repeat cleanup. This is not required to establish the documented P00-008/P00-009 access-control result.

## Immediate next task

### P00-015 — Create an operator signing key for evidence-manifest signing

**Scope:** Perform read-only signing-tool and protected-storage discovery for an operator signing key. Select a non-secret public-key algorithm and a host-local protected storage location before any key generation. Do not generate, display, export, or commit private-key material until a separately approved execution plan is confirmed.

**P00-014 completion evidence:**

- **Task status:** ✅ Complete and verified on 2026-10-03.
- **Evidence commit:** `54bde63816abe2f7015b20c87dfc50adcbd98a13` — `docs(phase-00): record P00-014 evidence vault validation`.
- **Repository lifecycle:** GitLab CI passed (pipeline identifier not captured); the commit was posted to GitHub; fetched verification proved `main == gitlab/main == origin/main == 54bde63816abe2f7015b20c87dfc50adcbd98a13`.
- **Vault:** `/srv/blockchain-soc/evidence-vault`, local ext4, empty, `soc-evidence:soc-evidence`, mode `0700`; `soc-evidence` traversal passed and interactive `kali` listing was denied.
- **Preservation:** P00-013 transfer ELF metadata remained unchanged. The VirtualBox shared folder remains transfer/staging only, not the authoritative vault.
- **RUNBOOK.md:** Not updated. P00-014 did not establish a complete reusable procedure for evidence admission, capacity planning, hashing, sealing, custody, retention, recovery, or destruction.

**P00-013 completion evidence:**

- **Task status:** ✅ Complete and verified on 2026-10-03.
- **Analysis input:** `ubuntu-server_P00-013_20261003T055707Z_working.elf`; `4,317,911,540` bytes.
- **Input SHA-256:** `e5184b85d82f1abb130fc726afecadc7f9b0c298f60b54be1dc6b3b487816f93`.
- **Tool:** Volatility 3 Framework `2.28.2`.
- **Validation:** Banner validation exited `0` at `2026-10-03T06:30:47Z`; `linux.pslist` exited `0` at `2026-10-03T06:44:50Z`; `linux.pstree` exited `0` at `2026-10-03T06:46:14Z`.
- **Symbols:** `Ubuntu_6.8.0-90-generic_6.8.0-90.91_amd64.json.xz`; symbol Git blob SHA-1 `cc2757b589e0af49fde532fc05a4c038c3b4a461`.
- **Result:** Process enumeration and parent/child hierarchy were plausible for the configured disposable Ubuntu lab host. This is a bounded process-focused validation only; it is not a malware finding, clean-host declaration, or comprehensive compromise assessment.
- **Evidence boundary:** Raw memory evidence, analysis logs, and symbol material remain outside Git under `/media/sf_VBox_Files_Shared/P00-013-Analysis/`. Do not stage or commit those items.
- **Documentation lifecycle:** Evidence commit `cd7731af8a5c50637e8d0ba3d6b624e68d04e97a` passed GitLab CI (pipeline identifier not captured), was posted to GitHub, and fetched verification proved `main == gitlab/main == origin/main == cd7731af8a5c50637e8d0ba3d6b624e68d04e97a`.
- **RUNBOOK.md:** Not updated. The available evidence does not establish a fully verified, reusable operator procedure with tested setup, cleanup, recovery, and troubleshooting.

**P00-015 explicitly out of scope:** Generating, displaying, exporting, copying, committing, or uploading a private signing key; signing any evidence or manifest; moving, deleting, sealing, or rehashing P00-013 evidence; changing the vault ownership model; changing Git remotes, GitLab CI, GitHub configuration, or `docs/.backup/`; starting MinIO/Object Lock; and `apt autoremove`.

**Expected files:** Protected host-local signing-key directory and key material outside Git after separate approval. Documentation changes only after factual validation: `docs/CHECKLIST.md` and `docs/HANDOFF.md`. `docs/RUNBOOK.md` changes only if a complete reusable signing-key procedure is tested and verified.

**Acceptance criteria:** Before key generation, identify installed signing tools, select an algorithm and protected local storage location, confirm private-key exclusion from Git and terminal output, and obtain explicit approval for the exact generation command.

**Validation commands:** Read-only discovery only until a separate key-generation action is explicitly approved. Do not add untested commands to the runbook.

**Dependencies:** P00-014 is complete and verified. The local service-account evidence vault exists, but its empty state must be preserved; do not place private operator signing material inside the evidence vault.

**Security constraints:** Never display, paste, log, copy to shared folders, or commit a private key, passphrase, seed, token, or raw evidence. Keep `docs/.backup/` untracked. Do not use force push.

## Subsequent task queue

1. `P00-014` — Prepare a dedicated evidence-vault directory/volume with separate service-account ownership.
2. `P00-015` — Create an operator signing key for evidence-manifest signing; keep private material outside Git.
3. `P00-GATE` — Audit Phase 0 before beginning Phase 1.

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
6. Reconcile documentation before staging: inspect every applicable CHECKLIST tracker row, detailed task record, acceptance checkbox, HANDOFF current-position/current-task field, historical-task heading, next-task reference, and applicable RUNBOOK status. Do not mark work `✅ Complete and verified` while required criteria remain unchecked or stale `current`, `pending`, `not run`, or pre-completion wording remains.
7. Run `git diff --check`, inspect the exact changed-file diff, perform a secret-safety review, and confirm that `docs/.backup/` remains untracked.
8. Commit implementation plus documentation together.
9. Open the next thread using the updated two files.

## Documentation reconciliation rule


Before every task-completion commit, the CHECKLIST tracker row, detailed task
record, acceptance criteria, HANDOFF current position/current task/completed
record, and applicable RUNBOOK procedure must describe the same factual state.
Use `✅ Complete and verified` only after required work and validation are
complete, documentation is reconciled, the commit has passed the GitLab-first
and GitHub-second publication workflow, and three-way SHA synchronization is
proved. Do not use completion, verification, pipeline, publication, or
synchronization language prospectively.


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

## GitLab Runner and CI smoke-test baseline

- Status: Verified.
- CI runner: Project-scoped local Docker executor runner using the `soc-docker` tag.
- Validation: The `runner_smoke_test` pipeline passed after validating repository checkout and required project-control files.
- Scope: Coursework/home-lab bootstrap only. Runner hardening for Docker isolation, no privileged mode, and no host mounts remains planned for the DevSecOps phase.
- Security note: Auto DevOps was disabled. Generic SAST, code-quality, container-scanning, secret-detection, and Semgrep jobs are intentionally deferred until the planned DevSecOps/security-gate phase.
- Repository synchronization: Local `main`, GitLab `main`, and GitHub `main` were verified at the same commit before this baseline record.
