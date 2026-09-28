# Blockchain SOC Enterprise V10.3 — Operations Runbook

## Status and scope

**Status:** Coursework/development runbook  
**Environment:** Local Kali Linux development environment and authorized test systems only  
**Production status:** Not a production deployment

This runbook documents verified procedures for initializing, operating,
validating, troubleshooting, and safely shutting down the Autonomous AI-Native
Blockchain Security Operations Center project.

Do not treat a procedure as verified until it has been executed successfully
and recorded with factual evidence.

## Safety boundaries

- Use only local fixtures, controlled testnets, throwaway environments, and
  systems you own or are explicitly authorized to test.
- Do not expose or commit passwords, tokens, private keys, seed phrases,
  Shamir shares, runner tokens, raw sealed evidence, or unredacted compliance
  data.
- Treat all logs, chain data, uploaded files, third-party text, and tool output
  as untrusted input.
- Agents are read-only by default.
- Sensitive actions require policy authorization and the correct human role.
- Use only documented, verified commands. Do not copy production commands into
  a coursework environment without review.

## Repository identity

Repository root:

```text
~/Blockchain-Security-Project-Remastered
```

Primary branch:

```text
main
```

Verified remotes:

```text
gitlab
  gitlab-soc:root/blockchain-security-project-remastered.git

origin
  git@github.com:ali4210/Blockchain-Security-Project-Remastered.git
```

## Pre-flight checks

From the repository root:

```bash
cd ~/Blockchain-Security-Project-Remastered

git status
git branch --show-current
git remote -v

git remote get-url gitlab
git remote get-url --push gitlab

git remote get-url origin
git remote get-url --push origin
```

Expected conditions:

- Current branch is `main`, unless a documented task requires another branch.
- Working tree is clean before starting an unrelated operational procedure.
- The remote names and URLs match the repository identity above.
- No secrets are displayed or copied into logs or commits.

## Project initialization

> Add only commands that have been tested in this repository.
> Do not replace this placeholder with guessed Docker, Python, Node, Anvil,
> database, policy-engine, or SIEM commands.

### Phase 0 — Environment and prerequisites

**Purpose:** Verify the Kali development environment and required tooling.

### P00-001 — Kali Linux update and baseline verification

**Status:** ✅ Verified

**Purpose**

Refresh configured package repositories, verify that the Kali VM is current and
package management is healthy, determine whether a reboot is required, and
record a sanitized OS/kernel baseline.

**Scope and limitations**

- Verified on the local Kali GNU/Linux Rolling coursework environment only.
- This procedure does not install project tooling, remove packages, start
  containers, or modify project application code.
- Do not run `apt autoremove` as part of this procedure unless a separately
  approved maintenance task requires it.

**Preconditions**

- Run from an authorized Kali VM session.
- Use an account permitted to invoke `sudo`.
- Review all APT errors, repository/key warnings, and package conflicts before
  proceeding to documentation or later tasks.
- Do not paste credentials, tokens, private keys, or sensitive configuration
  into terminal captures or project documents.

**Verified commands**

```bash
cd ~/Blockchain-Security-Project-Remastered

sudo apt update
sudo apt full-upgrade -y
sudo apt --fix-broken install -y

dpkg --audit
apt-mark showhold

if test -f /var/run/reboot-required; then
  echo 'REBOOT_REQUIRED=yes'
  cat /var/run/reboot-required
  test -f /var/run/reboot-required.pkgs && cat /var/run/reboot-required.pkgs
else
  echo 'REBOOT_REQUIRED=no'
fi

uname -a
cat /etc/os-release
```

**Verified expected result**

- `apt update` completes without repository or key errors.
- `apt full-upgrade -y` completes without unresolved package conflicts.
- `apt --fix-broken install -y` completes without repair errors.
- `dpkg --audit` and `apt-mark showhold` produce no output when the package
  database has no audit-detected unfinished state and no held packages.
- The reboot check prints either `REBOOT_REQUIRED=no`, or records the reason
  and affected packages when a reboot is required.
- `uname -a` and `/etc/os-release` capture the actual host baseline.

**Observed P00-001 result**

- Kali GNU/Linux Rolling 2026.3, `kali-rolling`.
- Kernel: `7.1.5+kali-amd64`, Kali `7.1.5-1kali1`, dated `2026-07-29`.
- APT reported all packages up to date; full upgrade required no package
  changes.
- `dpkg --audit` and `apt-mark showhold` produced no output.
- `REBOOT_REQUIRED=no`.
- APT listed unused automatically installed packages; no `apt autoremove` was
  run because package removal was out of P00-001 scope.

**Failure indicators and safe response**

- Repository, key, release-file, dependency, broken-package, or held-package
  errors appear.
- A reboot is required but cannot safely be performed in the current session.
- Do not apply unreviewed cleanup, repository, or package-removal commands.
  Preserve sanitized output, document the factual blocker, and resolve only the
  smallest required issue in a separately approved scope if needed.

**Evidence and provenance**

- Task: `P00-001`.
- Evidence: sanitized Kali terminal output for package update, package health,
  reboot check, and OS/kernel baseline.
- Prior evidence record commit:
  `6e6d9baf744495039e0271a19f170cf40b29a639`.
- This runbook entry is a documentation backfill. Its own commit, GitLab CI
  result where applicable, GitHub post, and three-way SHA synchronization must
  be verified before the runbook update is considered synchronized.

**Evidence to record**

- Sanitized command output.
- Tool versions.
- OS/kernel information if relevant.
- Git commit and GitLab CI result where applicable.

### P00-002 — Core Kali development prerequisites

**Status:** 🟧 Implemented but needs verification

**Purpose**

Verify the core Kali development prerequisites required by the project and install only a prerequisite demonstrated to be missing. This procedure validates Git, Node.js/npm, Python 3.11+, pip, Docker Engine, Docker Compose, Docker daemon health, and current-user Docker access.

**Scope and limitations**

- Verified on the local Kali GNU/Linux Rolling coursework environment only.
- The procedure installed only the missing `npm` package after inspecting command resolution, package ownership, package state, and APT policy.
- Docker Compose application-stack startup is not part of this procedure and remains deferred to P01-006.
- Foundry, Hardhat, Slither, Mythril, Certora, DFIR tools, Ollama, mTLS, project dependency installation, and application code are out of scope.
- Do not run `apt autoremove` under this procedure.

**Preconditions**

- Run from an authorized Kali session.
- Run the inspection commands before package installation.
- Review the APT transaction before accepting it; stop on unexpected removals, downgrades, conflicts, repository/key errors, or package-health failures.
- Do not paste passwords, tokens, private keys, wallet material, raw forensic evidence, or unredacted compliance data into terminal captures or project documents.

**Tested inspection commands**

```bash
cd ~/Blockchain-Security-Project-Remastered

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
```

**Tested targeted remediation**

```bash
sudo apt install npm
```

**Tested post-install validation**

```bash
npm --version
node --version
command -v npm
dpkg-query -W -f='${binary:Package}\t${Version}\t${Status}\n' nodejs npm
dpkg --audit
apt-mark showhold

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
```

**Observed P00-002 result**

- Git: `2.53.0`.
- Node.js: `v24.19.0`, provided by `nodejs 24.19.0+dfsg+~cs24.13.3-1`.
- npm was initially not installed; `sudo apt install npm` completed successfully.
- npm: `12.0.2`, installed as `npm 12.0.2+ds1-2` and available at `/usr/bin/npm`.
- Python: `3.14.7`; pip: `26.1.2`.
- Docker Engine: `29.8.1`; Docker Compose: `v5.5.1`.
- Docker service: `active`.
- `docker info` succeeded for the current user without `sudo`.
- `docker run --rm hello-world` completed successfully without privileged mode, host networking, host mounts, registry credentials, or Docker secrets.
- `dpkg --audit` and `apt-mark showhold` produced no output after installation.

**Expected successful result**

- Every required version command succeeds.
- Python reports version 3.11 or newer.
- `systemctl is-active docker` returns `active`.
- `docker info` returns Docker server details for the current user.
- `docker run --rm hello-world` prints its successful Docker message.
- `dpkg --audit` and `apt-mark showhold` produce no output.
- If npm is absent, APT reports successful installation and `npm --version` succeeds afterward.

**Failure indicators and safe response**

- A required command is absent after installation.
- APT proposes unexpected removals, downgrades, conflicts, or reports repository/key errors.
- `dpkg --audit` or `apt-mark showhold` returns output.
- Docker is inactive, `docker info` fails, or the current user receives a Docker socket permission error.
- The `hello-world` container fails.

Stop and preserve sanitized output. Do not run `apt autoremove`, reinstall unrelated tools, start the application stack, use privileged containers, or change Docker networking/mount settings. Resolve only the smallest P00-002 blocker in a separately reviewed step.

**Evidence and provenance**

- Task: `P00-002`.
- Evidence: sanitized Kali terminal output in the P00-002 implementation thread.
- Documentation commit, GitLab CI evidence, GitHub post, and three-way SHA synchronization: pending at the time of this entry.
- Coursework limitation: local development environment validation only; this does not establish production container or CI-runner hardening.

### Future phases

For every completed phase or operational component, add:

1. Purpose.
2. Prerequisites.
3. Safe initialization/start commands.
4. Health-check or validation commands.
5. Expected results.
6. Shutdown/cleanup commands.
7. Evidence paths.
8. Known limitations and coursework simulations.
9. Troubleshooting steps.

## Start procedure

> No verified project-wide runtime command has been recorded yet.

Add the exact tested startup procedure only after the relevant service stack
exists and is validated.

## Health checks and validation

> No verified project-wide health-check command has been recorded yet.

For each component, document:

```text
Component:
Prerequisite:
Command:
Expected healthy result:
Failure indicator:
Evidence to retain:
```

## Shutdown and cleanup

> No verified project-wide shutdown procedure has been recorded yet.

Before adding shutdown commands, verify that they do not delete required
evidence, local volumes, fixtures, or configuration.

## GitLab and GitHub synchronization

After an accepted local change has been validated and committed:

```bash
git push gitlab main
```

Wait for factual successful GitLab CI/CD evidence. Then:

```bash
git push origin main
```

Verify that all repositories point to the same commit:

```bash
git fetch gitlab
git fetch origin

printf 'local main:  '
git rev-parse main

printf 'GitLab main: '
git rev-parse gitlab/main

printf 'GitHub main: '
git rev-parse origin/main
```

Success condition:

```text
main == gitlab/main == origin/main
```

Do not use `git push --force`. If synchronization fails, stop, preserve the
factual error, record the blocker in `docs/HANDOFF.md`, and use the smallest
safe remediation.

## Troubleshooting

### Git remote synchronization differs

**Symptom:** Local `main`, `gitlab/main`, and `origin/main` return different
commit hashes.

**Safe diagnosis:**

```bash
git status
git log --oneline --decorate -10
git fetch gitlab
git fetch origin
git log --oneline --left-right main...gitlab/main
git log --oneline --left-right main...origin/main
```

**Safe response:**

- Stop before making unrelated changes.
- Do not force-push.
- Determine whether a remote-only commit exists.
- Record the exact state in `docs/HANDOFF.md`.
- Reconcile only after reviewing the divergence.

### GitLab CI failure

**Symptom:** The GitLab pipeline fails after `git push gitlab main`.

**Safe response:**

- Preserve the pipeline/job URL or sanitized job output.
- Do not push the unverified commit to GitHub under the normal workflow.
- Identify the failing job and smallest reproducible local validation.
- Fix only the active task issue.
- Commit the correction and repeat the GitLab-first workflow.

## Runbook maintenance

Update this runbook when:

- A new phase introduces a user-executable procedure.
- A startup, shutdown, validation, recovery, or troubleshooting command changes.
- A security control, approval requirement, or role boundary changes.
- A repeated failure reveals a safe, verified remediation procedure.
- The GitLab/GitHub synchronization process changes.

Before marking any runbook procedure as verified:

1. Execute it in an authorized environment.
2. Capture sanitized factual output.
3. Verify its expected result.
4. Confirm it does not expose secrets or raw sensitive evidence.
5. Commit the runbook update.
6. Push to GitLab `main`.
7. Confirm required GitLab CI success.
8. Push the same commit to GitHub `origin/main`.
9. Verify matching local, GitLab, and GitHub commit SHAs.

## Change log

| Date | Change | Verification | Commit |
|---|---|---|---|
| 2026-09-28 | Added verified P00-001 Kali update and baseline-verification procedure | Commands and observed results recorded from sanitized terminal evidence; synchronization evidence is documented in the P00-001 project ledger | Pending governance documentation commit |