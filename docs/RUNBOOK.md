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
- Documentation/evidence commit:
  `6e6d9baf744495039e0271a19f170cf40b29a639`.
- GitLab documentation pipeline was reported as succeeded; pipeline identifier
  and job URL were not captured.
- The same commit was posted to GitHub and synchronization was verified:
  `main == gitlab/main == origin/main ==
  6e6d9baf744495039e0271a19f170cf40b29a639`.

**Evidence to record**

- Sanitized command output.
- Tool versions.
- OS/kernel information if relevant.
- Git commit and GitLab CI result where applicable.

### P00-002 — Core Kali development prerequisites

**Status:** ✅ Verified

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
- Documentation/evidence commit:
  `bd7d284c50debf43330504721dea77bb8252d804`.
- GitLab Pipeline #12 passed; the same commit was posted to GitHub and
  synchronization was verified:
  `main == gitlab/main == origin/main ==
  bd7d284c50debf43330504721dea77bb8252d804`.
- Coursework limitation: local development environment validation only; this
  does not establish production container or CI-runner hardening.

### P00-003 — Foundry and Hardhat prerequisites

**Status:** ✅ Verified

**Purpose**

Install and validate the Foundry command-line tools (`forge`, `anvil`, and `cast`) and project-local Hardhat for the Kali coursework environment, while keeping project application work, networked chain activity, and later security tooling out of scope.

**Scope and limitations**

- Verified locally on Kali GNU/Linux Rolling only.
- Foundry `1.8.3` was installed through `foundryup`; the toolchain lives under `$HOME/.config/.foundry/bin`.
- Hardhat was installed as an existing project devDependency using npm; the generated `package-lock.json` is a tracked reproducibility artifact and `node_modules/` remains ignored.
- A temporary Foundry project was used only as a 🔒 coursework/local toolchain smoke test. It is not a production deployment, chain connection, audit, or project test suite.
- No persistent Anvil process, RPC endpoint, wallet material, private key, seed phrase, or Docker operation was used.
- Do not use `npx --no-install hardhat --help` as the validation command in this repository: without a root Hardhat configuration, it entered an interactive project-creation wizard. Exit it without selecting an option.

**Preconditions**

- Run from the authorized Kali account in `~/Blockchain-Security-Project-Remastered`.
- Node.js and npm must already be available from P00-002.
- Inspect command availability and repository state before installation.
- Obtain explicit scope approval before running project-local `npm install`.
- Never paste credentials, tokens, private keys, wallet material, raw evidence, or unredacted compliance data into captures or project files.

**Tested installation and persistence commands**

```bash
cd ~/Blockchain-Security-Project-Remastered

curl -L [https://foundry.paradigm.xyz](https://foundry.paradigm.xyz) | bash

export PATH="$PATH:/home/kali/.config/.foundry/bin"
foundryup

npm install --dry-run --ignore-scripts --no-audit --no-fund
npm install --ignore-scripts --no-audit --no-fund
```

Foundry PATH persistence was added as a guarded user-local block in `~/.zshrc`, outside the project repository:

```zsh
# >>> foundry PATH (P00-003) >>>
if [[ ":$PATH:" != *":$HOME/.config/.foundry/bin:"* ]]; then
  export PATH="$HOME/.config/.foundry/bin:$PATH"
fi
# <<< foundry PATH (P00-003) <<<
```

**Tested validation commands**

```bash
forge --version
anvil --version
cast --version

forge init --no-git /tmp/p00-003-foundry-smoke.Bg7RMq
cd /tmp/p00-003-foundry-smoke.Bg7RMq
forge build
cast to-wei 1 ether

cd ~/Blockchain-Security-Project-Remastered
npm ls --depth=0
npx --no-install hardhat --version
./node_modules/.bin/hardhat --version
zsh -ic 'forge --version; anvil --version; cast --version'
```

**Observed P00-003 result**

- `foundryup 0.0.8` was installed at `/home/kali/.config/.foundry/bin/foundryup`; installer output reported attestation and binary-integrity verification.
- `forge`, `anvil`, and `cast` each reported Foundry `1.8.3`, build commit `cae51ad458f6abb64852b7709eb784352429825d`.
- A fresh interactive zsh session resolved all required Foundry commands through the guarded PATH block.
- The temporary Foundry project initialized and built successfully; the build compiled 23 files with Solc `0.8.37`.
- `cast to-wei 1 ether` returned `1000000000000000000`.
- The exact temporary workspace was removed and its absence was verified.
- npm added 227 packages using `--ignore-scripts --no-audit --no-fund`.
- `package-lock.json` has lockfile version `3`; it records root Hardhat `^2.22.0`, resolved Hardhat `2.29.1`, TypeScript `5.9.3`, and tsx `4.23.15`.
- `npx --no-install hardhat --version` and `./node_modules/.bin/hardhat --version` each returned `2.29.1`.
- npm emitted deprecation warnings for transitive `glob@10.5.0` and `uuid@8.3.2`; remediation/audit is outside this task.

**Expected successful result**

- `forge --version`, `anvil --version`, and `cast --version` succeed from a fresh zsh session.
- The local Hardhat binary exists and both local-only version commands return the same installed version.
- `package.json` remains unchanged; `package-lock.json` exists; and `node_modules/` remains ignored.
- Temporary smoke-test material is removed after validation.
- No project source/configuration, Docker stack, persistent Anvil service, wallet/key material, or out-of-scope security tool is introduced.

**Failure indicators and safe response**

- Foundry bootstrap, attestation, integrity verification, download, extraction, or binary-version command fails.
- npm reports dependency-resolution, integrity, registry/TLS, permission, or blocking Node-engine errors.
- Hardhat local-only version validation fails or causes an unexpected package fetch.
- A command opens a project-creation wizard or would create root-level configuration/files.

Stop, preserve sanitized output, and do not start unrelated tooling, project tests, persistent services, scans, or package updates. Do not run `apt autoremove`. Resolve only the smallest documented blocker.

**Evidence and provenance**

- Task: `P00-003`.
- Evidence: sanitized Kali terminal output in the P00-003 implementation thread; GitLab Pipeline #13 passed.
- Documentation/lockfile commit: `473793554ceb7898b4b2165dfef401c47fa14d50` — `chore(phase-00): install Foundry and Hardhat prerequisites`.
- GitLab post / CI: posted to `gitlab/main`; Pipeline #13 passed.
- GitHub post: posted to `origin/main`.
- Synchronization: verified `main == gitlab/main == origin/main == 473793554ceb7898b4b2165dfef401c47fa14d50`.
- User-local `~/.zshrc` configuration is outside Git; repository-tracked P00-003 artifacts are `package-lock.json`, `docs/CHECKLIST.md`, `docs/HANDOFF.md`, and `docs/RUNBOOK.md`.

### P00-004 — Slither, Mythril, and Certora CLI prerequisites

**Status:** ✅ Verified

**Purpose**

Install and safely validate the local smart-contract security tooling required for later authorized coursework analysis: Slither, Mythril, and Certora CLI. This procedure validates installation, command availability, version/help behavior, and a credential-safe Certora state only. It does not run contract scans, symbolic analysis, or formal proofs.

**Scope and limitations**

- Verified on the local Kali GNU/Linux Rolling coursework environment only.
- Slither `0.11.6` and Certora CLI `8.19.2` are isolated in pipx-managed environments under `$HOME/.local/share/pipx/venvs`, with apps exposed under `$HOME/.local/bin`.
- Mythril runs from local Docker image `mythril/myth:latest`, validated at image digest `sha256:49e11758e359d0b410f648df5bbcba28a52e091a78e4772b5c02b9043666b4ff`.
- Mythril is containerized because the host Python is `3.14.7`, while the published Mythril pip support range used for this task did not cover that host version.
- Certora CLI installation and local help/version validation do not establish proof execution. Actual prover use requires an authorized personal access key; do not request, print, store, or commit the key.
- No project source/configuration files, package manifests, lockfiles, Docker Compose services, persistent chains, external/public targets, RPC connections, or scans are part of this procedure.

**Preconditions**

- Run as the authorized Kali user from `~/Blockchain-Security-Project-Remastered`.
- P00-002 Docker and Python/pip baseline is available.
- `pipx` and Docker are available to the current user.
- `$HOME/.local/bin` is present on `PATH` for pipx-exposed applications.
- Review command availability before installation.
- Never paste credentials, API keys, tokens, passwords, private keys, seed phrases, wallet material, raw evidence, or unredacted compliance data into terminal captures or repository files.

**Tested read-only inspection**

```bash
cd ~/Blockchain-Security-Project-Remastered

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

command -v pipx || true
pipx --version 2>&1 || true
docker --version 2>&1 || true
docker image inspect mythril/myth:latest 2>&1 || true
```

**Tested installation commands**

```bash
cd ~/Blockchain-Security-Project-Remastered

pipx install slither-analyzer==0.11.6
pipx install certora-cli==8.19.2
docker pull mythril/myth:latest
```

**Tested safe validation commands**

```bash
cd ~/Blockchain-Security-Project-Remastered

slither --version
certoraRun --version
certoraRun --help

if test -n "${CERTORAKEY-}"; then
  echo 'CERTORAKEY_STATUS=set (value intentionally not displayed)'
else
  echo 'CERTORAKEY_STATUS=not_set'
fi

docker run --rm   --network none   --read-only   --tmpfs /tmp:rw,noexec,nosuid,size=64m   --tmpfs /home/mythril/.solcx:rw,noexec,nosuid,size=64m   --cap-drop ALL   --security-opt no-new-privileges   mythril/myth:latest   myth version

docker run --rm   --network none   --read-only   --tmpfs /tmp:rw,noexec,nosuid,size=64m   --tmpfs /home/mythril/.solcx:rw,noexec,nosuid,size=64m   --cap-drop ALL   --security-opt no-new-privileges   mythril/myth:latest   myth --help
```

**Observed result**

- Initial inspection found no Slither, Mythril, or Certora CLI command and no corresponding host pip package metadata.
- `pipx 1.15.0` installed Slither `0.11.6` and Certora CLI `8.19.2` using Python `3.14.7`.
- `slither --version` returned `0.11.6`.
- `certoraRun --version` returned `certora-cli 8.19.2`; `certoraRun --help` rendered local CLI help.
- `docker pull mythril/myth:latest` completed; image inspection returned digest `sha256:49e11758e359d0b410f648df5bbcba28a52e091a78e4772b5c02b9043666b4ff`.
- The hardened Mythril container returned `Mythril version v0.24.8`; help rendered. Matplotlib issued a non-fatal temporary-cache warning under the permitted `/tmp` tmpfs.
- `CERTORAKEY_STATUS=not_set` was recorded without displaying any credential value. No Certora proof request was attempted.
- Repository boundary checks before and after validation showed no tracked project diff; `docs/.backup/` remained intentional untracked local recovery material.

**Expected successful result**

- `slither --version` reports the installed Slither version.
- `certoraRun --version` and `certoraRun --help` return local CLI output without a proof target or credential.
- Hardened Mythril version/help commands return output while retaining no network, no host mounts, no host Docker socket, a read-only root filesystem, tmpfs-only writable paths, no Linux capabilities, and no-new-privileges.
- No tracked project file changes occur from tool installation or validation.
- Certora proof execution is explicitly deferred when no authorized personal access key is configured outside Git and captured output.

**Failure indicators and safe response**

- A pipx install fails, an exposed command is absent from `PATH`, or a version/help command fails.
- Docker cannot pull or inspect the image, or the hardened Mythril command fails.
- Mythril reports cache-path write errors under a read-only root filesystem. Use only the documented disposable tmpfs mount for `/home/mythril/.solcx`; do not mount the repository or home directory, enable networking, add privileges, or weaken unrelated container controls.
- Certora indicates missing credentials for a proof request. Do not request or expose a key. Record that proof execution is deferred and keep any operator-managed credential outside Git, project files, terminal captures, and documentation.
- Stop on unexpected project-file changes; preserve sanitized output and resolve only the smallest P00-004 issue. Do not run a contract scan, proof, external-target test, Docker Compose stack, or `apt autoremove`.

**Evidence and provenance**

- Task: `P00-004`.
- Evidence: sanitized Kali terminal output from the P00-004 implementation thread.
- Verified tool versions: Slither `0.11.6`; Mythril `v0.24.8`; Certora CLI `8.19.2`.
- Coursework limitation: local prerequisite validation only. Tool installation and help/version checks are not a contract audit, proof, production deployment, or authorization to scan any target.
- Repository-tracked documentation artifacts: `docs/CHECKLIST.md`, `docs/HANDOFF.md`, and `docs/RUNBOOK.md`. Pipx environments and the Docker image are user-local/runtime state and are outside Git.

## P00-012 — Kali DFIR tooling baseline

**Status:** ✅ Complete and verified on 2026-10-02. Documentation closeout commit `3fa2735ee251f90a4dc46619e6bf85ebae0371c6` passed GitLab CI (green observed; pipeline identifier not captured), was posted to GitHub, and final verification proved `main == gitlab/main == origin/main == 3fa2735ee251f90a4dc46619e6bf85ebae0371c6`.

**Purpose:** Establish a minimal, host-local Kali DFIR tooling baseline for later authorized coursework work without collecting, opening, analyzing, signing, or modifying forensic evidence.

**Verified scope and results**

- Safely version/help validated: Sleuth Kit `4.14.0`; optional Autopsy `2.24-6kali1`; Volatility 3 `2.28.2` in a pipx-managed environment and exposed as `vol`; Plaso `20260119-1kali1` via packaged `plaso-*` utilities; dc3dd `7.3.1-4`; ewf-tools `20140816-2+b2`; YARA `4.5.8`; tshark `4.6.6`; tcpdump `4.99.6`; GnuPG `2.4.9`; and minisign package `0.12-1+b1` with CLI version `0.12`. Minisign was the sole package newly installed in the final reviewed transaction; GnuPG was already present and only safely validated.
- Optional Zeek was not installed. The available Kali package required `libc6 < 2.38`, conflicting with installed `libc6 2.43-4`. No forced install, libc downgrade, alternate repository, or workaround was attempted.
- Minisign’s reviewed transaction added exactly one package: `0 upgraded, 1 newly installed, 0 to remove and 0 not upgraded`. Its package state was `install ok installed`; `minisign -v` returned `minisign 0.12`; bare `minisign` rendered usage only.
- `dpkg --audit` returned no findings, and `apt-mark showhold` returned no held packages.

**Safety boundary**

- This task did not acquire disks, memory, packets, logs, or any live evidence.
- It did not start packet capture, run network analysis, launch Autopsy, execute a Plaso parse, open a case, or inspect case material.
- It did not generate, import, export, or use a signing key; create or verify a signature; or access private keys.
- It did not run `apt autoremove`, force package installation, downgrade system libraries, alter Git remotes, or change CI configuration.
- Package, pipx, and operator key state are host-local and must never be committed. `docs/.backup/` remains untracked local recovery material.

**Reusable validation pattern**

1. Start from the project directory and record `git status --short`.
2. Simulate the exact APT transaction before installation and review package count, dependency effects, removals, upgrades, and held-package state.
3. Install only the approved package set after reviewing the simulation. Do not run `apt autoremove`.
4. Validate each installed tool only with safe version or local help output. Do not provide an evidence file, capture interface, target, signing key, or case path.
5. For Minisign, safe validation is limited to `minisign -v` and bare `minisign` usage rendering; do not use `-G`, `-R`, `-C`, `-S`, or `-V`.
6. Run `dpkg --audit` and `apt-mark showhold`, then repeat `git status --short`.
7. If package health is not clean, an unexpected package transaction appears, Zeek remains incompatible, a tool requires case material, or repository paths change unexpectedly, stop and record only the factual blocker.

**Evidence and limitation**

- Task: `P00-012`.
- Evidence: sanitized Kali terminal output from the P00-012 implementation thread, including the reviewed Minisign transaction and safe validation.
- This establishes local host-preparation only. Installation and version/help output do not constitute forensic analysis, tool suitability for a specific evidence format, chain-of-custody validation, or authorization to collect evidence.
- Documentation closeout completed in commit `3fa2735ee251f90a4dc46619e6bf85ebae0371c6`: GitLab CI passed with green status (pipeline identifier not captured), the commit was posted to GitHub, and final fetched verification proved `main == gitlab/main == origin/main == 3fa2735ee251f90a4dc46619e6bf85ebae0371c6`.

## P00-015 — Protected Minisign evidence-manifest signing-key validation

**Status:** ✅ Verified

**Purpose:** Create and locally validate a dedicated passphrase-protected Minisign signing identity for future evidence-manifest detached signatures, without signing real evidence or exposing private material.

**Scope and limitations**

- Verified only on the authorized Kali coursework host.
- This procedure uses a harmless synthetic manifest solely to prove local sign-and-verify capability.
- It does not define a production evidence-manifest schema, publish a public key, establish a trust-distribution process, exercise revocation or rotation, or authorize signing real evidence.
- The evidence vault is not a signing-key store. Do not access or alter vault content as part of this procedure.

**Preconditions and safety boundaries**

- Perform discovery first and obtain explicit approval before generating private signing material.
- Use a dedicated host-local owner-only directory outside the repository, shared folders, `/tmp`, `docs/.backup/`, and the evidence vault.
- Enter the dedicated passphrase only at the interactive Minisign prompt. Never include it in shell arguments, environment variables, scripts, files, screenshots, logs, Git, or chat.
- Never display, copy, export, upload, edit, or inspect the private-key body.
- Use absolute paths for system utilities if the interactive shell cannot resolve ordinary commands.
- Stop if either intended key file already exists or if a synthetic test path already exists; do not overwrite or delete material automatically.

**Tested workflow**

1. Record repository state with `/usr/bin/git status --short`.
2. Inspect only metadata for the protected directory and intended key-file paths with `/usr/bin/stat`; confirm the directory is owner-only and both intended key files are absent before initial generation.
3. Generate the dedicated Minisign key pair with `/usr/bin/minisign -G`, supplying the private-key and public-key output paths only in approved host-local protected storage. Enter the new dedicated passphrase only at the interactive prompts.
4. Inspect file metadata only. Confirm private material is owner-readable only and the public verification file is not group-writable.
5. Create a generated non-sensitive synthetic manifest inside the protected signing directory, restrict it to owner-only access, and record its SHA-256 with `/usr/bin/sha256sum`.
6. Create a detached signature with `/usr/bin/minisign -S`, entering the passphrase only at the interactive prompt.
7. Verify with `/usr/bin/minisign -Vm` and the public verification file. The expected result is `Signature and comment signature verified` with exit status `0`.
8. After successful verification, remove only the explicitly named synthetic manifest and its detached signature with `/usr/bin/rm -f --`; confirm both are absent.
9. Repeat `/usr/bin/git status --short`. The protected host-local files must remain outside Git.

**Expected successful result**

- Dedicated signing material exists only in protected host-local storage.
- The private key is owner-readable only; the protected directory is owner-only; public verification material is not group-writable.
- Synthetic detached signing and verification both return exit status `0`.
- Only the named synthetic test files are removed after successful verification.
- No repository file, raw evidence, evidence-vault content, or shared-folder content is signed or modified.

**Failure indicators and safe response**

- A target key file or synthetic test file exists unexpectedly: stop; do not overwrite, regenerate, or delete it.
- Key generation, signing, or verification returns a nonzero status: preserve sanitized output and inspect metadata only. Do not retry automatically.
- Cleanup is incomplete: do not remove additional files; retain only the named synthetic artifacts for controlled review.
- A passphrase or private-key body appears in any output or proposed diff: stop, do not stage the content, remove it from tracked material, and perform a targeted secret-boundary review.
- The repository shows unexpected tracked changes: stop and review the diff before proceeding.

**Evidence and limitation**

- Task: `P00-015`.
- Factual local result: Minisign key generation, synthetic detached signing, and public-key verification each succeeded; synthetic test artifacts were removed.
- This is a coursework/local cryptographic-control validation, not a production key-management system, evidence-sealing process, public-key distribution mechanism, or authorization to sign real evidence.
- Documentation closeout commit `f34e97b18cb3cee417d1c2b3fc618ef676271773` was posted to GitLab, reported green in GitLab CI (pipeline identifier not captured), posted to GitHub, and fetched verification proved `main == gitlab/main == origin/main == f34e97b18cb3cee417d1c2b3fc618ef676271773`.

## P00-006 — Windows Ollama loopback backend and Caddy private-interface proxy

**Status:** ✅ Verified

**Purpose:** Run the authorized Windows Ollama backend only on a loopback, non-default endpoint and present the API only through a Caddy reverse proxy bound to the approved private interface.

**Scope and limitations:**

- Verified locally on the authorized Windows inference host as a coursework/development configuration.
- Ollama and Caddy run in separate normal-user foreground PowerShell sessions; this is not a persistent Windows service arrangement.
- The proxy is plaintext HTTP for this task only. mTLS is deferred to P00-007, bearer authorization to P00-008, and Kali-to-Windows authenticated validation to P00-009.
- Docker Desktop/Open WebUI, Windows Firewall changes, model pulls/removals, and public/internet exposure are outside this procedure.

**Prerequisites:**

- Ollama is installed and the approved local model inventory is present.
- Caddy is installed and available as `caddy`.
- The approved Windows private-interface address is `192.168.0.189`.
- No conflicting Ollama or Caddy process is listening on the specified ports.

**Safety boundaries:**

- Bind Ollama only to `127.0.0.1:11435`.
- Bind Caddy only to `192.168.0.189:11434`.
- Do not bind either service to `0.0.0.0`, `[::]`, or an unintended adapter.
- Do not commit host-local configuration, model-store paths, credentials, certificates, or tokens.
- Do not start Docker/Open WebUI or perform Kali-to-Windows tests in this procedure.

**Verified configuration:**

Create a host-local Caddyfile outside the repository with automatic HTTPS and Caddy administration disabled, an explicit `bind 192.168.0.189`, and a `reverse_proxy 127.0.0.1:11435` site at `http://192.168.0.189:11434`. Validate it with:

```powershell
caddy validate --config <host-local-Caddyfile> --adapter caddyfile
```

**Verified startup:**

1. In a normal-user PowerShell session, set process-local `OLLAMA_HOST` to `127.0.0.1:11435` and process-local `OLLAMA_MODELS` to the existing approved host-local model store, then run `ollama.exe serve`.
2. Confirm startup output reports `Listening on 127.0.0.1:11435`.
3. In another normal-user PowerShell session, run:

   ```powershell
   caddy run --config <host-local-Caddyfile> --adapter caddyfile
   ```

4. Confirm Caddy reports that its administration endpoint is disabled and its HTTP listener is `192.168.0.189:11434`.

**Verified health checks:**

```powershell
Invoke-RestMethod http://127.0.0.1:11435/api/tags
Get-NetTCPConnection -State Listen
Invoke-RestMethod http://192.168.0.189:11434/api/tags
```

- Direct backend health returned a `models` field containing four models.
- Listener inspection showed Ollama solely at `127.0.0.1:11435` and Caddy solely at `192.168.0.189:11434`.
- Proxy health returned a `models` field containing four models.

**Expected healthy result:** Direct backend health and private-interface proxy health each return four models. Ollama is not a private-interface listener; Caddy is the sole listener at `192.168.0.189:11434`.

**Failure indicators and safe response:**

- If Caddy returns HTTP `502`, verify the foreground Ollama process is still running and that direct loopback `/api/tags` succeeds before restarting Caddy.
- If Caddy appears on `[::]:11434`, stop it and use an explicit `bind 192.168.0.189` directive before retesting.
- If Ollama returns zero models, stop it and verify the correct existing local model store is supplied only as a process-local environment value. Do not pull, delete, move, or copy models as part of recovery.
- If either service acquires an unexpected listener, stop the affected foreground process and correct its explicit binding before proceeding.

**Shutdown:** In each foreground service window, press `Ctrl+C`. Confirm no `ollama.exe` or `caddy.exe` process remains before changing bindings or restarting a validated session.

**Evidence and provenance:**

- Task: `P00-006`.
- Evidence: sanitized Windows PowerShell listener tables, Caddy validation output, direct backend health, and proxy health in the P00-006 implementation thread.
- Factual local validation: four direct models and four proxied models.
- Documentation/evidence commit: `f9856ed4c181cb6740e7f26043e96a54d3ec0853`; GitLab Pipeline #20 passed; the same commit was posted to GitHub; `main == gitlab/main == origin/main == f9856ed4c181cb6740e7f26043e96a54d3ec0853`.

## P00-008/P00-009 — Temporary Bearer-enforced mTLS gateway validation

**Status:** ✅ Verified

**Purpose:** Validate the approved temporary path from Kali to the Windows Caddy gateway while preserving loopback-only Ollama and loopback-only Bearer verification.

**Verified architecture:**

```text
Kali client
  -> https://ollama-mtls.home.arpa:11434
  -> Caddy server certificate validation and required client certificate
  -> loopback-only forward-auth verifier at 127.0.0.1:11436
  -> loopback-only Ollama backend at 127.0.0.1:11435
```

**Sanitized validation record:**

- Server certificate identity was aligned with the Caddy site name using `DNS:ollama-mtls.home.arpa` and `IP:192.168.0.189`.
- Caddy configuration validation succeeded and strict SNI/Host enforcement remained enabled with TLS client authentication.
- A request without a client certificate failed during TLS negotiation with no HTTP response.
- A valid mTLS request without Bearer returned HTTP `401`.
- A valid mTLS request with the configured Bearer caused the verifier to record an allow decision.
- The authenticated root-route request returned HTTP `403` after authorization; it is not evidence of token rejection.
- During testing, direct Kali access to Ollama and verifier ports timed out, and all temporary processes/listeners were stopped after validation.

**Operational constraints:**

- Never print, commit, or place a Bearer token in shell history, a command line, a document, or a screenshot.
- Keep the Caddyfile, CA material, server key, client key, and token in approved host-local protected storage only.
- Do not make the temporary runtime persistent, alter firewall policy, or expose Ollama/verifier directly to the LAN.
- If an application-level success response is required, use one separately approved temporary `GET /api/tags` request through the same protected path and perform cleanup immediately afterward.

**Evidence and provenance:**

- Tasks: P00-008 and P00-009.
- Sanitized evidence: Windows and Kali terminal validation output; no token, certificate body, or private-key material is recorded here.
- Documentation closeout: `e9c788688ae2cd18187eb5710d22837e0aaf3d9f` — `docs(phase-00): record P00-008 and P00-009 validation`.
- Publication state: GitLab CI passed, the same commit was posted to GitHub, and `main == gitlab/main == origin/main == e9c788688ae2cd18187eb5710d22837e0aaf3d9f`.
- Runtime state after validation: temporary Caddy, verifier, and Ollama processes stopped; temporary listeners released.

## P00-007 — Private PKI and Caddy mTLS static validation

**Status:** ✅ Verified

**Purpose:** Create a private coursework certificate authority, issue a Windows proxy server certificate and a Kali client certificate in host-local protected storage, and configure Caddy to require and verify a client certificate before reverse-proxying to the loopback-only Ollama backend.

**Scope and limitations:**

- Verified on the authorized Kali VM and Windows inference host as a coursework/development configuration.
- Certificate material and the Windows-local Caddyfile remain host-local and outside the repository.
- This procedure records only sanitized metadata, validation outcomes, permissions/ACL outcomes, and static configuration validation.
- Caddy and Ollama were not started after the mTLS configuration change; no live listener check, mTLS handshake, bearer-token check, or Kali-to-Windows inference request occurred.
- Bearer authorization and live authenticated cross-host verification were deferred at the time of this P00-007 procedure. They were subsequently completed under the approved temporary P00-008/P00-009 validation documented above.
- This is not a production PKI lifecycle: no certificate revocation service, rotation automation, persistent Windows service, or firewall validation was performed.

**Prerequisites:**

- P00-006 loopback/private-interface separation is already verified: Ollama remains loopback-only and Caddy is the sole intended private-interface proxy.
- OpenSSL is available on the authorized Kali and Windows hosts.
- Caddy is installed on the Windows host.
- Approved host-local protected storage locations exist for PKI material.
- The approved private-interface address is `192.168.0.189`.

**Safety boundaries:**

- Never print, commit, or transmit CA private keys, server/client private keys, certificate bodies, CSRs, passwords, tokens, or raw secret-bearing command output.
- Keep all PKI material and host-local Caddy configuration outside Git.
- Caddy must reference only the server certificate, matching server private key, and CA certificate; it must not reference the CA private key.
- Preserve Ollama loopback binding at `127.0.0.1:11435`; do not expose Ollama directly to the LAN.
- Do not start Docker/Open WebUI, change firewall policy, or run an authenticated Kali-to-Windows inference request in this procedure.

**Verified local validation:**

- Kali CA self-verification succeeded.
- Kali client certificate chain and `sslclient` purpose validation succeeded.
- Kali client private key and client certificate public keys matched.
- Windows server certificate chain and `sslserver` purpose validation succeeded.
- Windows server certificate contained the approved private-interface IP in its subject alternative name and had TLS Web Server Authentication usage.
- Windows server private key and server certificate public keys matched.
- Kali time synchronization was active and synchronized before final certificate validation.
- Temporary shared-folder certificate copies were absent during final Kali validation.
- Caddy static validation returned `Valid configuration` for the host-local mTLS configuration.
- Caddy recognized the configured TLS client-authentication policy; static validation exited without starting a server.

**Verified Caddy policy:**

- Caddy administration is disabled.
- Persisted runtime configuration is disabled.
- Automatic HTTPS is disabled because a private-CA-issued server certificate is configured explicitly.
- The intended HTTPS site address is the approved private-interface address and port `11434`.
- Caddy presents the private-CA-issued server certificate and matching private key.
- Caddy requires and verifies a client certificate against the private CA.
- Caddy reverse-proxies only to `127.0.0.1:11435`.

**Expected static-validation result:**

```text
Valid configuration
```

The legacy trusted-CA-file deprecation and formatting warnings were subsequently addressed through an approved host-local maintenance step: the configuration now uses `trust_pool file`, is formatted, and final `caddy validate` returned `Valid configuration` with exit code `0`. A timestamped host-local backup was created and its SHA-256 matched the final Caddyfile. This maintenance did not start Caddy or Ollama, change listeners, perform a live mTLS handshake, or authorize bearer-token or cross-host inference testing. Treat any future Caddy syntax or formatting change as a separately reviewed maintenance change followed by validation.

**Failure indicators and safe response:**

- Certificate chain or purpose validation fails, certificate validity time is incorrect, or a key/certificate public-key comparison fails: stop and investigate only the affected host-local PKI artifact; do not regenerate or copy key material without an approved scope.
- The server certificate does not contain the approved private-interface IP in its subject alternative name: do not start Caddy; correct certificate issuance in a separate controlled task.
- Caddy static validation fails: do not start Caddy; preserve sanitized error output and restore or inspect only the host-local Caddy configuration.
- A private key, token, or certificate body appears in terminal output or a proposed Git diff: stop, do not stage it, remove it from tracked content, and perform a targeted secret-boundary review.
- Caddy or Ollama is unexpectedly running, or ports `11434`/`11435` are unexpectedly listening during static validation: stop and investigate before any further configuration change.

**Evidence and provenance:**

- Task: `P00-007`.
- Evidence: sanitized Kali and Windows terminal output in the P00-007 implementation thread.
- Factual validation: CA/client/server certificate validation, key/certificate match checks, protected-storage permission/ACL checks, Kali NTP synchronization verification, repository secret-boundary scan, and Caddy static validation.
- Documentation/evidence commit: `3eb7d51225622833d7813d64bb9dd343ad8e3f62` — `docs(phase-00): record P00-007 mTLS static validation`.
- GitLab post / CI: posted to `gitlab/main`; GitLab Pipeline #23 passed.
- GitHub post: posted to `origin/main`.
- Synchronization: verified `main == gitlab/main == origin/main == 3eb7d51225622833d7813d64bb9dd343ad8e3f62`.

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

### P01-007 — Project dependency installation with PEP 668-safe Python isolation

**Status:** ✅ Verified on 2026-10-05
**Scope:** Local development dependency verification only; not a dependency-upgrade, audit-remediation, or production packaging procedure.

**Purpose**

Install the existing Node.js and Python requirements while preserving tracked
manifests, avoiding system-Python modification, and respecting the repository's
ignored local dependency directories.

**Prerequisites**

- Run from the repository root with `node`, `npm`, and `/usr/bin/python3`
  available.
- Confirm `package.json`, `package-lock.json`, and `requirements.txt` are
  tracked and review `git status` before installation.
- Preserve `docs/.backup/` as untracked; do not inspect or stage it.
- Do not use `sudo`, `--break-system-packages`, `npm audit fix`,
  `npm audit fix --force`, or lifecycle-script approval as part of this
  procedure.

**Verified commands**

```bash
cd ~/Blockchain-Security-Project-Remastered

/usr/bin/npm install
/usr/bin/npm ls --depth=0

/usr/bin/python3 -m pip install -r requirements.txt
```

On Kali, the system pip command can be correctly blocked by PEP 668. If that
occurs, use the ignored project-local virtual environment instead:

```bash
/usr/bin/python3 -m venv .venv

.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m pip show requests langgraph
.venv/bin/python -c 'import requests, langgraph; print(requests.__version__); print("langgraph=import-ok")'
```

**Expected successful result**

- `npm install` and `npm ls --depth=0` return zero.
- The existing Node dependency tree resolves without changing tracked
  `package.json` or `package-lock.json`.
- Either system pip succeeds, or PEP 668 safely blocks system installation and
  the `.venv/` fallback succeeds.
- `requests` and `langgraph` are present and import successfully from `.venv/`.
- `requirements.txt` remains unchanged, and `.venv/` remains ignored.

**Warnings and limitations**

- `npm install` may report known vulnerabilities or blocked lifecycle scripts.
  Record those facts, but do not run audit remediation, force remediation, or
  approve blocked scripts without separate scope and review.
- PEP 668 blocking system pip is expected protection on Kali; do not override
  it with `--break-system-packages`.
- This procedure does not pin, upgrade, remove, or audit dependencies, nor does
  it validate application behavior beyond dependency presence and imports.

## Start procedure

### P01-006 — Docker Compose Redis stub verification

**Status:** ✅ Verified on 2026-10-05
**Scope:** Local development-skeleton verification only; not a production deployment procedure.

**Purpose**

Validate the existing `docker-compose.yml` Redis stub without changing Compose
configuration, host sysctl settings, application code, evidence material, or
unrelated containers.

**Prerequisites**

- Run from the repository root.
- Docker Engine and the Docker Compose plugin are available to the current user.
- The Docker daemon is reachable.
- No unrelated container is using host port `6379`.
- Preserve `docs/.backup/` as untracked; do not inspect or stage it.

**Verified commands**

```bash
cd ~/Blockchain-Security-Project-Remastered

DOCKER=/usr/bin/docker
PROJECT=blockchain-security-project-remastered
COMPOSE_FILE=docker-compose.yml

"$DOCKER" compose --project-name "$PROJECT" -f "$COMPOSE_FILE" config --quiet

"$DOCKER" compose --project-name "$PROJECT" -f "$COMPOSE_FILE" up -d redis
"$DOCKER" compose --project-name "$PROJECT" -f "$COMPOSE_FILE" ps

"$DOCKER" compose --project-name "$PROJECT" -f "$COMPOSE_FILE" \
  exec -T redis redis-cli ping

"$DOCKER" compose --project-name "$PROJECT" -f "$COMPOSE_FILE" \
  logs --no-color --tail=100 redis
```

**Expected successful result**

- Configuration validation succeeds.
- Only the named project’s `redis` service and network are created.
- `redis-cli ping` prints `PONG`.
- Redis logs include `Ready to accept connections tcp`.

**Warnings and limitations**

- Docker Compose may warn that the top-level `version` attribute is obsolete.
  This warning is non-blocking for the validated existing skeleton file; do not
  alter `docker-compose.yml` solely during verification.
- Redis may warn that `vm.overcommit_memory` is not enabled. Record the
  warning, but do not change host sysctl configuration as part of this
  verification.
- A successful `PONG` verifies basic Redis readiness only; it does not establish
  production hardening, persistence, authentication, TLS, policy enforcement,
  or evidence-vault behavior.

## Health checks and validation

Use the in-container health check rather than treating a running container
state as sufficient:

```bash
"$DOCKER" compose --project-name "$PROJECT" -f "$COMPOSE_FILE" \
  exec -T redis redis-cli ping
```

Treat `PONG` together with the Redis readiness log as the P01-006 success
condition. Preserve sanitized status and log output if startup or readiness
fails; do not change unrelated Docker, Compose, host, or repository settings
while diagnosing.

## Shutdown and cleanup

After status and logs have been captured, remove only the named verification
project’s containers and network:

```bash
"$DOCKER" compose --project-name "$PROJECT" -f "$COMPOSE_FILE" \
  down --remove-orphans

"$DOCKER" compose --project-name "$PROJECT" -f "$COMPOSE_FILE" ps -a
```

Expected result: the named project has no remaining containers. Do not add
volume-removal flags, remove images, prune Docker resources, or stop unrelated
containers as part of this verification.

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
| 2026-09-28 | Added verified P00-001 Kali update and baseline-verification procedure | Commands and observed results recorded from sanitized terminal evidence; GitLab pipeline reported succeeded; GitHub post and three-way synchronization verified | `6e6d9baf744495039e0271a19f170cf40b29a639` |

## P03-001 — Local formal-tool analysis

**Procedure status:** ✅ Locally validated and reconciled with implementation `7110f725e89ee6c0d185474b8f2a5685f1814aef` on 2026-10-07: reported green GitLab CI, GitHub publication, and fetched three-way synchronization verified. Scanner/proof evidence is local, not CI execution.

### Preconditions

- Use only the tracked intentionally vulnerable coursework fixture; never deploy or fund it.
- Verified compiler: `~/.local/share/blockchain-soc/toolchains/solc-0.8.24/solc`.
- Verified isolated Z3: `~/.local/share/blockchain-soc/toolchains/z3-4.12.2/`; expected library hash must come from distribution verification, not arbitrary current bytes.
- Slither 0.11.6 and digest-pinned Mythril v0.24.8 image must already exist. The runner does not install or download dependencies.
- No Certora credentials, RPC, deployments, funding, host bind mounts, or privileged containers.

### Validated invocation

From `~/Blockchain-Security-Project-Remastered`:

```bash
/usr/bin/node scripts/run-formal-tools.cjs \
  --execute-approved-fixture \
  --z3-sha256 \
  5ba701bbb32fc0923ee98b4adb1b246f7ef60c30fa62065514d8099955678101
```

Recorded integrated execution exited 0: two Slither findings, three Mythril findings, CHC deposit safe, CHC ordering unknown, and BMC ordering violated. Evidence: `~/.local/state/blockchain-soc/p03-001/integrated-Ttw0qi/`.

### Interpretation and bounds

- Execution success is not contract security acceptance or project closeout.
- Findings remain retained. Mythril exit 1 is accepted only with successful, error-free, findings-bearing JSON.
- SMT safe, violated, unknown, unavailable, and error are distinct; diagnostics must match the selected assertion and engine.
- Assertions use instrumented source copies; BMC is function-level, not a drain exploit or whole-contract reachability proof.
- Mythril uses Paris-target creation bytecode, optimizer disabled, three transactions, depth 128, 120-second execution budget, 10000-ms solver-query budget, and 360-second outer timeout.
- Container uses the pinned digest, explicit non-root user, no network, read-only root, dropped capabilities, no-new-privileges, finite resources, and tmpfs-only writes.

### Evidence and recovery

- Each run creates host-local `integrated-*` artifacts outside Git. Review summary, reports, compiler diagnostics, process status, and container cleanup.
- Preserve failed runs. The timed-out integrated run and shorter-budget zero-finding run are not successful evidence.
- Cleanup removes only the uniquely named container; if unconfirmed, inspect that exact name before retrying. Do not perform broad deletion.
- Stop on missing prerequisites, checksum mismatch, unavailable solvers, tool errors, or absent expected fixture detection. Do not bypass integrity or isolation controls.
- Local regression suite reported 23 passing with Hardhat `--no-compile`. Implementation `7110f725e89ee6c0d185474b8f2a5685f1814aef` passed reported green GitLab CI; pipeline ID/URL and individual job/test-count logs were not captured. CI includes the regression invocation but does not run scanners/proofs.
- Original fixture, raw artifacts, installed toolchains, and `docs/.backup/` are not included in staging.

## P03-002 — Software composition analysis

**Procedure status:** ✅ Complete and verified within documented scope 2026-10-07 at implementation `bfd7ca3af23c5ebf0c6b491fc4b85ebef0d61f9e`: reported green GitLab CI, GitHub publication, and fetched three-way synchronization verified. Completion reconciliation `29888c04636e00e4089b47770614ed0b72e0a0a8` passed reported green GitLab CI, was published to GitHub, and fetched synchronization was verified before P03-003 started. Pipeline ID/URL and individual job logs not captured.

### Scope and prerequisites

- Use the integrity-approved package.json, package-lock.json, and requirements.txt; the runner pins their hashes.
- Requires Node.js and the existing project `.venv` for metadata inspection. It installs nothing and performs no automatic fixes.
- npm inventory consumes exact locked versions, including optional/platform entries; installed npm state is not proved.
- Python inventory consumes all installed project-venv distributions, including tooling/extras. It is not a Python lockfile, fresh resolution, or proof of dependency closure.
- Live mode sends public ecosystem/package/version coordinates to OSV and CVE aliases to NVD. No API credentials or project source are sent.

### Validated commands

From `~/Blockchain-Security-Project-Remastered`:

```bash
/usr/bin/bash scripts/run-sca.sh --inventory
/usr/bin/bash scripts/run-sca.sh --lookup-approved-public-dependencies
```

The live run exited 0: 249 npm and 39 Python coordinates, 10 matched coordinates, 32 active advisories, 28 requested/returned NVD CVEs, no missing IDs. Evidence: `~/.local/state/blockchain-soc/p03-002/sca-MSfaq3/`.

### Interpretation and limits

- `lookup-completed` means in-scope lookup requests finished, not that dependencies are safe or findings remediated.
- Advisory IDs, CVE IDs, affected coordinates, and exploitability are different concepts. Retain advisory-only records, withdrawn status, and missing enrichment.
- NVD Deferred/Awaiting Analysis records and differing score sources/versions remain explicit. Record presence and CVSS scores do not prove project exposure.
- OSV batch pagination is per query; full advisories are retrieved separately. NVD requests use up to 100 CVE IDs with offset pagination and 6500-ms pacing.
- HTTP transport permits only the defined HTTPS service URLs, rejects redirects, omits credentials, limits responses to 8 MiB, and bounds individual requests to 45 seconds.
- Finite request/page/detail limits and a 15-minute request deadline apply; this is not an exact process wall-clock guarantee. Cache is per-run only; no automatic retries or stale fallback.

### Evidence and failure recovery

- Inventory, request/response records, lookup output, summary, and failures are written under host-local `~/.local/state/blockchain-soc/p03-002/sca-*/`, outside Git.
- Live execution owns `lookup.lock` to prevent overlapping runs of this runner. Successful/handled-error paths release it.
- Do not blindly delete an existing lock. Investigate its recorded process and evidence first; never remove an active run's lock.
- Exit 2 or error/incomplete evidence is not a successful zero-finding scan. Preserve partial responses and failure records.
- Do not disable TLS, bypass hashes, install packages, run audit fixes, or change the approved dependency baseline to obtain a clean result.
- Local regression suite reported 49 passing. Implementation `bfd7ca3af23c5ebf0c6b491fc4b85ebef0d61f9e` passed reported green GitLab CI; pipeline ID/URL and individual job/test-count logs were not captured. Existing CI invocation includes offline regressions; CI does not execute live SCA or require the local `.venv`.
- Keep raw reports, installed environments, lock artifacts, and `docs/.backup/` out of staging. Protected dependency inputs remain tracked and unchanged.

## P03-003 — Local IAST state-transition evidence

**Procedure status:** ✅ Verified within documented coursework scope 2026-10-07 at implementation `139ff6a3310675aa6482b1c57cd9b53760d6b364`: reported green GitLab CI, GitHub publication, and fetched synchronization verified. Completion reconciliation `20d5d55bf8056db33c9bb21095554238ea86c67e` passed reported green GitLab CI, was published to GitHub, and fetched synchronization was verified before P03-004 started. Pipeline ID/URL and individual job logs not captured.

### Purpose and scope

Capture root-frame opcode execution and selected committed storage transitions during disposable, in-process, non-forked Hardhat tests. This is a coursework simulation, not production monitoring or an exploit proof.

### Prerequisites and safety

- Use existing repository-local Hardhat and the integrity-approved dependency/configuration/fixture inputs.
- Native fixture runner requires existing `~/.local/share/blockchain-soc/toolchains/solc-0.8.24/solc`, SHA-256 `fb03a29a517452b9f12bcf459ef37d0a543765bb3bbc911e70a87d6a37c30d5f`.
- Do not substitute npm solc 0.8.26, change the exact fixture pragma, install ethers, enable a fork, or configure an external RPC.
- Runtime insertion and simulated value operate only inside an owned local snapshot. No constructor/deployment or real funding is tested.
- Wrappers reject nested execution and writes outside selected slots; they do not provide complete world-state coverage.

### Tested commands

From `~/Blockchain-Security-Project-Remastered`:

```bash
./node_modules/.bin/hardhat \
  --config config/hardhat.config.js \
  test --no-compile \
  test/hardhat/formal-tools.test.js \
  test/hardhat/placeholder.test.js \
  test/hardhat/pipeline-entrypoints.test.js

/usr/bin/timeout 180s /usr/bin/node scripts/run-iast.cjs \
  --execute-approved-local-fixture

./node_modules/.bin/tsx --no-cache scripts/ingest-manifests.mts
```

Observed results: 61 local passing tests; native runner exited 0 with `status: "iast-executed"`; strict ingestion valid and asset inventory unchanged.

Implementation `139ff6a3310675aa6482b1c57cd9b53760d6b364` passed reported green GitLab CI. Pipeline ID/URL, individual job logs, and remote test count were not captured. Native compiler integration remains separately recorded local evidence.

### Evidence interpretation

- Four native-runtime cases recorded ledger 0→100→60; zero and insufficient withdrawals failed without changing 60.
- Synthetic regressions recorded successful writes and attempted writes discarded by REVERT.
- CALL-before-SSTORE is observed ordering, not proof of a reentrancy drain.
- Only selected slot before/after values are committed-state evidence; opcode writes are attempts.
- Snapshot code/balance/storage/block restoration was confirmed.
- Evidence: `~/.local/state/blockchain-soc/p03-003/iast-L6LCQu/`; retain compiler records, captures, cleanup, and summary outside Git.
- `taskComplete: false` is the saved runtime snapshot, not a documentation/publication lifecycle decision. Do not edit saved evidence to change task status.

### Failure handling and limits

- Stop on hash mismatch, compiler error, malformed/conflicting trace, unsupported frames/slots, ambiguous transaction identity, or cleanup failure. These are incomplete coverage, not empty findings.
- Compiler has a 60-second timeout and 16-MiB output buffer; the tested runner has an outer 180-second limit.
- Transaction gas is at most 300000; calldata at most 4096 bytes; storage scope at most 64 slots.
- Trace processing rejects over 20000 steps or 8 MiB JSON after provider return. This is not a provider-level memory cap.
- Snapshot cleanup is attempted on handled execution errors; a forced process termination ends this private in-process network, but does not produce confirmed cleanup evidence.
- Keep evidence and backups out of staging. No automatic dependency fixes, compiler download, configuration bypass, external chain connection, or real funding.
- Existing CI runs wrapper/runner-boundary regressions; native compiler execution remains separately recorded local evidence.

## P03-004 — Local Solidity AST masking

**Procedure status:** ✅ Verified within documented scope 2026-10-07 at implementation `42384867ed4a8f2fcda2b58e806ce967a802cd37`: reported green GitLab CI, GitHub publication, and fetched synchronization verified. Completion reconciliation `6b6469779454d1820a9a59f8be5f3d07fa213912` passed reported green GitLab CI, was published to GitHub, and fetched synchronization was verified before P03-005 started. Pipeline ID/URL and individual job logs not captured.

### Purpose and prerequisites

Produce an allowlisted structural AST projection with opaque literal/name hashes and explicit manual-review/error outcomes. This is not a recompilable AST, semantic security check, secret-redaction system, or complete prompt-injection defense.

Requires existing repository-local tsx and native `~/.local/share/blockchain-soc/toolchains/solc-0.8.24/solc`, SHA-256 `fb03a29a517452b9f12bcf459ef37d0a543765bb3bbc911e70a87d6a37c30d5f`. The native adapter disables import callbacks and requests parsing/AST only. Do not substitute compiler versions, alter the fixture pragma, or install a parser package to bypass errors.

### Tested commands

From `~/Blockchain-Security-Project-Remastered`:

```bash
./node_modules/.bin/hardhat \
  --config config/hardhat.config.js \
  test --no-compile \
  test/hardhat/formal-tools.test.js \
  test/hardhat/placeholder.test.js \
  test/hardhat/pipeline-entrypoints.test.js

/usr/bin/timeout 60s ./node_modules/.bin/tsx --no-cache \
  scripts/ast-mask.mts --approved-local-fixture

./node_modules/.bin/tsx --no-cache scripts/ingest-manifests.mts
```

Observed: 73 local passing tests; native fixture CLI exited 0 with `status: "masked"`; strict ingestion valid and asset inventory unchanged.

Implementation `42384867ed4a8f2fcda2b58e806ce967a802cd37` passed reported green GitLab CI. Pipeline ID/URL, individual job logs, and remote test count were not captured. Native Solc 0.8.24 fixture parsing remains separately recorded local evidence.

### Output and evidence

- `maskContractAst(source, options?)` returns serialized JSON, not rewritten source.
- `masked` contains projection-version-1 structural nodes; non-success results omit the AST.
- Literal hashes use decoded bytes; names/member names are also hashed. Raw source, paths, documentation, type-description text, literal value/hexValue, and diagnostics are not returned.
- Original fixture result: 64 nodes, maximum semantic depth 10, five literal masks including four string masks, two documentation fields omitted.
- Evidence: `~/.local/state/blockchain-soc/p03-004/mask-Ytb4y1/`; masked result and summary remain outside Git.
- Existing CI uses npm Solc 0.8.26 on compatible in-memory parser examples; native original-fixture parsing uses Solc 0.8.24 locally.
- Saved `taskComplete: false` is runtime evidence, not a publication-status field. Do not modify it to declare completion.

### Limits and safe failure handling

- Semantic depth counts AST nodes from SourceUnit=1; arrays/containers do not increase that measure; documentation/type metadata are omitted.
- Default depth 32, hard ceiling 64; options may lower node/output limits within supported bounds.
- Source cap 256 KiB; AST JSON cap 8 MiB; at most 10000 semantic nodes, 100000 traversed containers, and container depth 256.
- Compact projection cap 2 MiB; final metadata/pretty evidence formatting add overhead. These are not complete process-memory guarantees.
- Native compiler timeout 30 seconds/maxBuffer 8 MiB; tested CLI outer limit 60 seconds.
- CLI exit 0 means masked projection, 2 means manual review, 1 means invalid/error. Nonzero results are not sanitized acceptance or empty findings.
- Imports, inline assembly, unknown node types/operators, unsupported syntax attributes, and over-limit inputs must not produce an accepted partial AST.
- Manual-review status requires operator handling; no production review queue or LLM forwarding is implemented.
- Do not echo raw compiler diagnostics, weaken import controls, increase hard limits, install substitutes, or edit protected inputs to force acceptance.
- Keep evidence and documentation backups unstaged. P03-005 owns the tracked prompt-injection fixture and its dedicated validation.

## P03-005 — Prompt-injection fixture verification

**Procedure status:** ✅ Verified within documented fixture-specific scope 2026-10-07 at implementation `f85cd49fae29a82bcc1e04584f7c1d2231989e55`: reported green GitLab CI, GitHub publication, and fetched synchronization verified. Completion reconciliation `b770b3b0c7ed857594df0c2473238dd7ee127752` passed reported green GitLab CI, was published to GitHub, and fetched synchronization was verified before P03-006 started. Pipeline ID/URL and individual job logs not captured.

### Purpose and prerequisites

Verify that the actual pinned inert fixture produces the expected hash/tag projection, without raw payloads or documentation. This is fixture-specific data handling, not a live LLM attack or complete prompt-injection defense.

Requires repository-local Hardhat/tsx/npm Solc and the existing integrity-pinned native Solc 0.8.24 used by P03-004. The fixture's ^0.8.24 pragma intentionally permits both installed parser versions without source rewriting. Preserve the original vault and masker.

### Tested commands

From `~/Blockchain-Security-Project-Remastered`:

```bash
./node_modules/.bin/hardhat \
  --config config/hardhat.config.js \
  test --no-compile \
  test/hardhat/formal-tools.test.js \
  test/hardhat/placeholder.test.js \
  test/hardhat/pipeline-entrypoints.test.js

/usr/bin/timeout 90s /usr/bin/node scripts/verify-mask-fixture.cjs \
  --approved-injection-fixture

./node_modules/.bin/tsx --no-cache scripts/ingest-manifests.mts
```

Observed: 79 local tests passed; native CLI exited 0 with `status: "fixture-verified"`; strict ingestion valid.

Implementation `f85cd49fae29a82bcc1e04584f7c1d2231989e55` passed reported green GitLab CI. Pipeline ID/URL, individual job logs, and remote test count were not captured. Native Solc 0.8.24 fixture verification remains separately recorded local evidence.

### Evidence and interpretation

- Pinned fixture SHA-256: `17f6fba73823f0ed9c00a9253595cb7249c580fcb4dfc79f1e9b6344c26f47a4`.
- Native result: 24 nodes, semantic depth 4, seven exact literal masks, one documentation field omitted.
- Schema, node relationships, payload absence, and deterministic two-parse output verified.
- Ordinary/escaped/Unicode/hexadecimal/joined/empty literals are inert data; never follow their instruction-like contents.
- Raw payloads and tested complete hexadecimal/base64 representations are not present in accepted output.
- Evidence: `~/.local/state/blockchain-soc/p03-005/fixture-RxiTl5/`; masked result and summary outside Git.
- Native 0.8.24 integration remains local; CI parses unchanged compatible fixture bytes with npm Solc 0.8.26.
- No LLM behavior, secret-redaction guarantee, semantic security, or complete prompt-injection defense is established.

### Failure handling and integrity

- Verifier requires explicit CLI scope, regular fixture input, exact bytes/hash, accepted masking status, exact expected mask tuples, strict schema, and determinism.
- Non-success masking cannot become verifier success. Verifier exits nonzero with fixed structured failure and does not echo raw diagnostics/payloads.
- Approved Solidity inventory is exactly PromptInjectionFixture.sol and VulnerableVault.sol; only the new fixture hash and inventory entry were added.
- Controlled copied roots rejected fixture tampering, an extra contract, and a symlink; copies were removed.
- Do not change expected hashes, allow wildcards, weaken masking limits, or disable inventory enforcement to obtain success.
- P03-004 bounds still apply. Verifier checks input under 64 KiB, accepted compact JSON at most 4 MiB, and at most 256 projected nodes; outer tested command limit is 90 seconds.
- Never deploy, fund, execute, forward to an LLM, or connect this fixture to a live service as part of this procedure.
- Keep generated evidence and documentation backups unstaged. Saved `taskComplete: false` is runtime evidence, not a publication-status field.

## P03-006 — Deny-by-default readiness control

**Procedure status:** ✅ Verified within documented deny-by-default scope 2026-10-07. P03-006 is ✅ Complete and verified within that scope: implementation `b5f7c8e411740f420b2adc883671cf3e740d6aeb`; evidence closeout `f4a8bd3bd27e0334d5c32d50004931da2cef2a2e` and final status correction `54346bd68089c74e449b3f9801ef60d6d23c7b8c` completed user-reported green GitLab CI, GitHub publication, and fetched three-way synchronization. Original closeout/status pipeline IDs not captured. Live hardware integration and positive readiness remain unconfigured; Task 6 is not the current task.

### Scope and prerequisites

Controls explicit production-readiness requests on protected main. It does not reject an already accepted Git push, deploy anything, or establish hardware health. Policy SHA-256: `eef3af1f3adca840147cd4bae30623710c0705ba2ecb38e269e344af941009ff`.

Hardware checker is unconfigured and no production allow path exists. Normal verification success is not production readiness. Preserve branch rules, protected inputs, and the deny-by-default policy. Authorized coursework/development environment only; not a production deployment.

### Tested local commands

From `~/Blockchain-Security-Project-Remastered`:

```bash
./node_modules/.bin/hardhat \
  --config config/hardhat.config.js \
  test --no-compile \
  test/hardhat/formal-tools.test.js \
  test/hardhat/placeholder.test.js \
  test/hardhat/pipeline-entrypoints.test.js

/usr/bin/node scripts/production-readiness.cjs --check-production-readiness

./node_modules/.bin/tsx --no-cache scripts/ingest-manifests.mts
```

Observed: 87 local tests passed; local readiness exited 1 with blocked status, invalid local CI context, unconfigured hardware, and all authorization fields false; strict ingestion valid. Evidence: `/home/kali/.local/state/blockchain-soc/p03-006/local-vqhg6hij`.

### Verified CI behavior and evidence

Both runs used implementation `b5f7c8e411740f420b2adc883671cf3e740d6aeb`, main, project 1, and report member `artifacts/production-readiness.json`.

| Run | Pipeline/job | Factual outcome |
|---|---|---|
| Ordinary verification | 94 / 129 | Pipeline and gate success; allow_failure false; status not-requested, requested false, ciMetadataValid true; productionReady/deploymentAuthorized/releaseAuthorized/taskComplete false. |
| Explicit readiness request | 95 / 132 | Pipeline and gate failed with script_failure; allow_failure false; requested true, blocked, ciMetadataValid true, hardware-check-unconfigured; hardware unconfigured, executed false, adapterConfigured false; all authorization fields and taskComplete false. |

- Requested run smoke 130 and ingestion 131 succeeded. Gate artifact identified the expected hardware-check-unconfigured blocking reason.
- CLI --ci consumes selected CI metadata and non-secret PRODUCTION_READINESS_REQUESTED intent. Absent/false intent may permit ordinary verification without readiness; true intent fails while hardware checking is unconfigured. Unknown context/intent, altered policy, and mock/demo flags cannot grant readiness.
- Success/failure report uploads were read for both runs. Retention configured for 7 days; complete retention lifecycle not tested. Timeout may prevent upload on another run.
- Requested-report SHA-256: `34d515f7bc625486ef684cbf44ffe7dfdea5edd744efb94e4782eca1c51cac97`.
- Pipeline metadata: `/home/kali/.local/state/blockchain-soc/p03-006/ci-request-q6et6s7t`; downloaded requested report/metadata: `/home/kali/.local/state/blockchain-soc/p03-006/pipeline-95-artifact-1prtdqgb`. Ordinary report readback is terminal evidence, not a newly saved local report.
- Terminal verification used the installed application service and read-only project/pipeline/job-scoped artifact queries. Do not repeat pipeline creation to inspect existing evidence. No new untested operator command introduced by this reconciliation.
- Metadata validity is structural, not cryptographic authentication. taskComplete false is runtime evidence, not a repository-publication-status field.

### Safe failure handling

- Exit 1 on the readiness request is the intended safety result, not a bypass target. Ordinary success is not production authorization.
- Do not enable allow_failure, remove the job, fake CI/hardware metadata, or relabel not-requested as ready.
- No live collector/attestation, healthy production path, or live-cluster outage drill verified. Do not install a cluster or invent thresholds under this procedure.
- Policy parsing checks at most 8 KiB after file read; local evidence capture checks at most 32 KiB output. These are not complete process-memory bounds.
- Keep evidence and documentation backups unstaged. No kubeconfig/private material, hardware provisioning, cluster contact, deployment, or signing is required for this deny-only procedure.
- Future hardware integration requires a separately approved target, capabilities, trustworthy bounded collector, and factual validation. This evidence does not resolve that dependency or authorize deployment/release.
- Evidence closeout `f4a8bd3bd27e0334d5c32d50004931da2cef2a2e` and final status correction `54346bd68089c74e449b3f9801ef60d6d23c7b8c` are published and fetched-synchronized after reported green GitLab CI. P03-007 is now the authorized task; Phase 3 remains incomplete.

## P03-007 — Coursework job-plane runtime audit

**Procedure status:** ✅ Verified within explicitly accepted 🔒 coursework job-plane scope 2026-10-07. Evidence commit `bcb2f997f6061aeeeafe2b006d01a9337656ea75` and final green-status correction `6779157de76e2a6f821568e49b6d18901eb71d3b` completed user-reported green GitLab CI, GitHub publication, and fetched synchronization. Pipeline IDs not captured. Manager and other isolation limitations unchanged; Task 7 publication is complete and Task 8 is current.

### Purpose and accepted boundary

Verify actual Zone 2 build, predefined-helper, and cache-init execution on existing runner 2 without privileged mode, host bind/engine-socket mounts, added capabilities/devices, or observed host namespace sharing. Docker-managed local volumes are permitted.

The trusted manager retains host networking and a read-write host Docker socket. This is an accepted and disclosed control-plane dependency, not a claim of manager/whole-host isolation. Jobs used bridge networking; separate per-job networks, non-root execution, all-capabilities-dropped behavior, service isolation, and container-escape resistance were not established.

### Preconditions and safety

- Authorized local coursework GitLab/Docker environment; existing Runner 19.4.1, runner ID 2.
- Tested commit `54346bd68089c74e449b3f9801ef60d6d23c7b8c`; existing CI definition and package metadata pinned before the run.
- Inspect runner configuration in memory using a strict output allowlist. Never print/save tokens, configuration bodies, environment values, raw labels, or job traces.
- Start external create/start observation before a bounded pipeline; do not mount Docker into jobs to let them inspect themselves.
- Do not remove the manager socket, restart services, register another runner, alter cache settings, weaken the readiness policy, or install host dependencies merely to obtain a pass.

### Tested execution

Pipeline 98 ran the unchanged existing CI. Its ingestion job 140 executed:

```bash
npm ci --ignore-scripts --no-audit --fund=false

./node_modules/.bin/hardhat \
  --config config/hardhat.config.js \
  test --no-compile \
  test/hardhat/formal-tools.test.js \
  test/hardhat/placeholder.test.js \
  test/hardhat/pipeline-entrypoints.test.js

./node_modules/.bin/tsx --no-cache scripts/ingest-manifests.mts
```

These commands were exercised inside the existing CI job, not installed or newly run on the Kali host by this audit. The ingestion output was directed to its configured artifact. Job success observed; remote test count not extracted. Do not reuse the prior 87 local tests as an observed remote count.

The tested terminal audit used Docker create/start events filtered by project/commit labels, selected-field container inspection, volume-driver inspection, and actual GitLab job-ID correlation. The complete tested inline audit command is in the sanitized P03-007 terminal record for pipeline 98. This runbook does not introduce a new shortened pipeline-creation command or an untested replay procedure.

Audit creation used the normal installed application service and verified project/actor/ref, with non-secret P03_007_ISOLATION_AUDIT=runtime-v1 and PRODUCTION_READINESS_REQUESTED=false. Existing matching audit records prevented automatic repeats.

### Verified results

| Job | ID | Result |
|---|---:|---|
| runner_smoke_test | 139 | Success on runner 2 |
| ingest_manifests | 140 | Success on runner 2 |
| production_readiness_gate | 141 | Success on runner 2; ordinary non-readiness-request run |

- Pipeline 98 succeeded; all three jobs had allow_failure false.
- Twelve containers with runtime start events: three builds, three predefined helpers, six cache-init.
- All snapshots reported privileged false, bridge network, no host PID/IPC/UTS setting, no added capabilities/devices, no host bind/socket mounts, and empty violations.
- Observed managed volumes used the local driver with zero options and no configured host-device/bind backing. This is not a statement that Docker volumes have no host storage.
- Observer errors empty; build/helper coverage present for every job.
- Services absent from the inspected CI and not exercised; do not extrapolate this result to future service jobs.
- jobPlaneRuntimeChecksPassed true. Saved taskComplete false was deliberate and remains historical data, not a checklist/publication state.

### Evidence and integrity

- Evidence: `/home/kali/.local/state/blockchain-soc/p03-007/runtime-rt95oop1/runtime-audit.json`.
- SHA-256: `d293a791f0762ee5e1725c9a34124cbbcaa78992d5872bf956fe67ee1b46ace4`.
- CI definition SHA-256: `188ce8a3c990f40c2f1179e4dac498a47b5262a5c54cd65287f61ae81cb4eea6`.
- package.json SHA-256: `e5814463f435a5ccb4f7901c09cd3935125b8fc32bd59f094c087ca2f61506df`.
- Saved-evidence readback verified the digest, pipeline/jobs, 12-container count, observed starts, and empty violations without changing the report.
- No CI/source/test/runner/policy/dependency/lockfile changes were required. This closeout modifies only task documentation; evidence and backups remain unstaged.

### Failure handling and limitations

- Missing helper/build start coverage is incomplete evidence, not a pass. A bind/socket/privilege/device/namespace violation is a failed check.
- Unknown driver/backing metadata cannot be accepted as safe by omission.
- Do not automatically rerun creation after timeout or unknown outcome; retain the pipeline ID and saved partial evidence.
- Do not retroactively change runtime snapshots, report booleans, or manager limitations to obtain acceptance.
- Inspect saved evidence before authorizing another run. No cleanup of manager volumes or unrelated containers is part of this procedure.
- A future manager-hardening, service, rootless, dedicated-network, or stronger isolation claim requires separate scope and factual validation.
- P03-007 evidence and final status publication are complete at fetched-synchronized final commit `6779157de76e2a6f821568e49b6d18901eb71d3b`. The user authorized P03-008; no repeat Task 7 audit is required.

## P03-008 — Lynis technical audit and sanitized NIST evidence

**Procedure status:** ✅ Verified within approved Lynis/NIST technical scope 2026-10-07; P03-008 evidence is complete and verified. Implementation/evidence `ae73cc80efd63fc2ce00942818e53e85b1e6a14a` completed GitLab-first publication with user-reported green CI, GitHub publication, and fetched three-way SHA equality. Pipeline ID/job URL not captured. Documentation closeout reconciled. Tested commands and technical limitations are unchanged.

### Purpose and scope

Use approved open-source Lynis as a non-root technical-baseline provider on the authorized Kali VM. Normalize its report through a bounded data-only adapter. This is not CSET execution, a full NIST/CMMC organizational assessment, an official crosswalk, certification, remediation, or production authorization.

Project-authored relationships: ACCT-9628 to AU-12, FINT-4350 to SI-7. Both actual entries remain needs-review/fullControlAssessed false. Unmapped valid findings are retained; absence of findings never proves a control pass.

### Provider and timer boundary

Reviewed package lynis=3.1.6-1 installed as exactly one new Kali package with no upgrades/removals. Program version and package ownership verified. Host package state is outside Git.

Installation enabled/started lynis.timer. Before correction it was active/waiting; observed trigger and service-start timestamps were empty and service inactive. The timer was disabled/stopped explicitly, leaving timer inactive/disabled and service inactive. Do not infer a lifetime history from empty observed timestamps. No already-running service audit was stopped.

Tested commands:

```bash
/usr/bin/sudo /usr/bin/apt-get \
  --no-install-recommends --no-upgrade install lynis=3.1.6-1

/usr/bin/sudo /usr/bin/systemctl disable --now lynis.timer

/usr/sbin/lynis --version
/usr/sbin/lynis show help
/usr/sbin/lynis show options
```

Initial --help produced usage-related exit 64; the advertised show help/options commands returned 0. Version 3.1.6 verified; dpkg --audit and apt-mark showhold produced no output. Do not reinstall or ignore arbitrary nonzero results.

### Tested non-root acquisition

The verified run used the following command inside an owner-only working directory, under a Python-managed 300-second limit with private stdout/stderr and process-group termination on timeout:

```bash
/usr/sbin/lynis audit system \
  --quick --no-colors --no-plugins \
  --profile /etc/lynis/default.prf \
  --log-file /home/kali/.local/state/blockchain-soc/p03-008/lynis-kedsab88/lynis.private.log \
  --report-file /home/kali/.local/state/blockchain-soc/p03-008/lynis-kedsab88/lynis-report.private.dat
```

This historical command is not an instruction to overwrite or rerun against those evidence files. A future audit requires fresh protected paths, timer/service checks, approved scope, and bounded capture.

Observed UID 1000, exit 0, duration 73.77 seconds, no timeout. No upload, remote-audit, pentest, forensics, or remediation option used; plugins disabled. Network isolation was not claimed. Non-root/organizational coverage remains incomplete.

All raw log/report/stdout/stderr and process metadata remain protected outside Git; recorded files had mode 0600 and parent directory 0700. Do not paste or commit them.

### Tested adapter and regressions

From the repository root:

```bash
/usr/bin/node --check scripts/governance-core.cjs
/usr/bin/node --check scripts/run-governance.cjs
/usr/bin/node --check test/hardhat/placeholder.test.js

./node_modules/.bin/hardhat \
  --config config/hardhat.config.js \
  test --no-compile \
  test/hardhat/formal-tools.test.js \
  test/hardhat/placeholder.test.js \
  test/hardhat/pipeline-entrypoints.test.js

./node_modules/.bin/tsx --no-cache scripts/ingest-manifests.mts

/usr/bin/node scripts/run-governance.cjs \
  --report /home/kali/.local/state/blockchain-soc/p03-008/lynis-kedsab88/lynis-report.private.dat \
  --metadata /home/kali/.local/state/blockchain-soc/p03-008/lynis-kedsab88/process-metadata.json
```

The real adapter invocation was captured by the private Python normalization wrapper, which verified source digests, expected counters, false authorization claims, and saved owner-only output. Do not redirect output to a world-readable file or commit a generated report by default.

Observed: 105 local passing tests, including 18 governance regressions; strict ingestion valid with unchanged approved asset map; Node syntax and git diff --check passed. GitLab CI user-reported green for evidence `ae73cc80efd63fc2ce00942818e53e85b1e6a14a`; pipeline ID/job URL and remote test count not captured. CI executes synthetic adapter regressions, not a Lynis audit of the CI host.

### Real results and interpretation

- Four warning records and 46 suggestion records retained: total 50.
- Two records have partial AU-12/SI-7 relationships; 48 remain unmapped, not discarded.
- Both control-evidence states needs-review; no complete control assessment.
- Provider hardening index 63 is not NIST compliance percentage.
- Provider tests-done counter 267 is not NIST-control coverage or proof all privileged checks passed.
- Normalized status review-required is expected, not an integration failure.
- nistComplianceEstablished/cmmcCertificationEstablished/productionReady/deploymentAuthorized/releaseAuthorized/taskComplete all false. Runtime taskComplete is not task/publication status.

### Parsing and privacy safeguards

The first adapter rejected one hyphenated omitted field and two finding-text continuation lines. The real report matched the narrowly approved compatibility shape before patching.

The corrected parser drops supported hyphenated host fields and contiguous non-assignment finding-text continuations. It does not publish those names/descriptions. Continuations limited to 4 KiB each/eight consecutive/256 total. Orphan/empty/oversized/excessive/forbidden/critical malformed records remain rejected.

Required scalar duplicates, malformed IDs/timestamps, policy alteration, failed/root/timed-out acquisition records, unsupported versions/hashes, duplicate/prototype-shaped JSON keys, invalid UTF-8, oversized input, symlinked final file components, and unsupported CLI modes fail with fixed JSON errors and no raw diagnostics.

Limits: report 2 MiB; metadata 32 KiB; policy 8 KiB; output 256 KiB; report 30000 lines/256 KiB per line; 1024 finding records/512 grouped records; JSON depth 32/node budget 20000. These do not establish complete process-memory bounds. O_NOFOLLOW applies to the final file component, not all ancestors.

Provenance verifies structural acquisition fields and byte digests, not signed identity or tamper-proof independent attestation. Completion timestamps and successful process metadata are checked; finish-marker presence alone is not proof of execution.

### Evidence and identities

- Acquisition directory: `/home/kali/.local/state/blockchain-soc/p03-008/lynis-kedsab88`.
- Raw report SHA-256: `e353c841131b7a4469d291d963099b40be86e4e13242bbf34ffdbb646ad71b77`.
- Process metadata SHA-256: `b919a39e66b3eebd094786e343450add5a14b34597d246d72a2cf5b241e031d1`.
- Sanitized result: `/home/kali/.local/state/blockchain-soc/p03-008/normalized-_t8qnj0l/governance-result.json`.
- Sanitized SHA-256: `4b30d711cf1126f7d93db54f7d3237ce8b5f128cb05eec14780d3aaf85420d26`.
- Pinned policy SHA-256: `7de534c7fb32284e5c0fec30aa4cc95ea13a4722d993188fe446c7fdd1c76684`.
- Provider executable SHA-256: `a3de3e245c436671347cc13c199f3115b8d88493deb5a78cd999b00a041d1976`.
- Profile SHA-256: `49ffbf504febedeea096fbbb8730825c4805dfaac747c6e530a22174fd77f30f`.
- Implementation backups outside Git: implementation-b4i06qff and format-fix-cell1z8b under the Task 8 private state directory.

### Failure handling and closeout

- Do not edit raw reports, metadata, counts, hashes, or warnings to force success.
- Do not automatically reinstall, rescan, enable timers, run sudo audits, remediate host findings, or broaden parser acceptance after a failure.
- Preserve evidence and return masked diagnostics; no raw logs/report bodies in chat or Git.
- Do not represent project relationships as official crosswalks, unassessed controls as passed, or tooling success as compliance.
- No Phase 4 enrichment, source fixture, CI, dependency manifest/lockfile, ingestion, readiness, runner, branch-rule, or remote change is part of this integration.
- Task 8 implementation/evidence `ae73cc80efd63fc2ce00942818e53e85b1e6a14a` completed reported green GitLab CI, GitHub publication, and fetched synchronization. Documentation closeout is complete and reconciled. Proceed to P03-009 upon verification. Preserve the review-required findings and all false runtime compliance/authorization/taskComplete flags.

## P03-009 — Local Foundry exploit and invariant test verification

**Status:** ✅ Verified

**Purpose**

Verify smart contract reentrancy exploit mechanics and state invariants using Foundry in a hermetic local environment without external network connectivity, chain deployments, or live funds.

**Scope and limitations**

- Validated on local Kali Linux with Foundry 1.8.3.
- Targets in-memory `contracts/solidity/VulnerableVault.sol` fixture only.
- Coursework simulation: tests demonstrate reentrancy state reversion/drainage and ledger accounting balance under fuzzing, not production mainnet monitoring.

**Verified commands**

```bash
cd ~/Blockchain-Security-Project-Remastered
forge test -vvv
./node_modules/.bin/tsx --no-cache scripts/ingest-manifests.mts
./node_modules/.bin/hardhat --config config/hardhat.config.js test --no-compile test/hardhat/placeholder.test.js
```

**Verified expected result**

- `ExploitTest` passes all tests.
- `InvariantsTest` passes fuzzing runs (256 runs, 128,000 calls).
- Ingestion verifier emits `status: "valid"` with intact asset map.
- 83 Hardhat regression tests pass.

## P03-010 — DeFi front-running detector interface and safe stub validation

**Status:** ✅ Verified

**Purpose**

Validate the typed front-running detection interface for calldata-copying and gas-outbidding analysis, confirming safe fallback behavior when live mempool feeds are unconfigured pending Phase 11 consensus monitoring.

**Scope and limitations**

- Validated locally on Kali Linux development environment.
- Evaluates static/fixture mempool snapshots only; does not establish live P2P network connections, RPC mempool listeners, or trade execution.
- Safe stub explicitly returns status `pending_phase_11_mempool` when no live feed snapshot is provided.

**Verified commands**

```bash
cd ~/Blockchain-Security-Project-Remastered
python3 -m unittest discover -s test/agents/ -p "test_*.py"
./node_modules/.bin/tsx --no-cache scripts/ingest-manifests.mts
./node_modules/.bin/hardhat --config config/hardhat.config.js test --no-compile test/hardhat/placeholder.test.js
```

**Verified expected result**

- Unit tests pass 5/5 verifying safe stub fallback, empty snapshots, gas outbidding detection, and NotImplementedError on unbuilt future phase functions.
- Ingestion verifier emits `status: "valid"` with intact asset map.
- 83 Hardhat regression tests pass.

## P03-011 — DeFi rug-pull AST signature scanner validation

**Status:** ✅ Verified

**Purpose**

Validate static AST analysis for detecting common DeFi rug-pull patterns: unrestricted minting, untimelocked liquidity extraction, unsafe centralized ownership, and hidden post-launch fee manipulation.

**Scope and limitations**

- Evaluates static Solidity AST nodes/dictionaries; does not interact with live blockchains or execute contracts.
- Detects known modifier omissions, timelock absences, and fee caps exceeding 25% basis points.

**Verified commands**

```bash
cd ~/Blockchain-Security-Project-Remastered
python3 -m unittest discover -s test/agents/ -p "test_*.py"
./node_modules/.bin/tsx --no-cache scripts/ingest-manifests.mts
./node_modules/.bin/hardhat --config config/hardhat.config.js test --no-compile test/hardhat/placeholder.test.js
```

**Verified expected result**

- Unit tests pass 7/7 verifying detection of all four rug-pull categories, clean contract handling, front-running tests, and P03-012 stub behavior.
- Ingestion verifier emits `status: "valid"` with intact asset map.
- 83 Hardhat regression tests pass.

## P03-012 — Flash-loan invariant test synthesis validation

**Status:** Verified

**Purpose**

Synthesize and validate Foundry invariant test fixtures that simulate extreme flash-loan borrowing to test protocol solvency and oracle price manipulation bounds.

**Scope and limitations**

- Generates standalone Solidity invariant test contracts targeting in-memory fixtures.
- Does not submit live mainnet transactions or require external RPC connectivity.

**Verified commands**

```bash
cd ~/Blockchain-Security-Project-Remastered
python3 -m unittest discover -s test/agents/ -p "test_*.py"
./node_modules/.bin/tsx --no-cache scripts/ingest-manifests.mts
./node_modules/.bin/hardhat --config config/hardhat.config.js test --no-compile test/hardhat/placeholder.test.js
```

**Verified expected result**

- Unit tests pass 7/7 verifying default and custom invariant synthesis parameter substitution.
- Ingestion verifier emits `status: "valid"` with intact asset map.
- 83 Hardhat regression tests pass.

## P03-GATE — Phase 3 completion gate verification

**Status:** Verified

**Purpose**

Verify all Phase 3 DevSecOps shield components before permitting Phase 4 storage and MCP middleware implementation.

**Scope and limitations**

- Validates static analysis, SCA inventory, IAST state transitions, AST literal masking, prompt-injection fixture neutralization, deny-by-default CI readiness gate, runner isolation, Lynis NIST baseline, Foundry exploit/invariant tests, and DeFi attack detection stubs.
- Coursework simulation: all analyses run against local fixtures; no live mainnet interactions.

**Verified commands**

```bash
cd ~/Blockchain-Security-Project-Remastered
./node_modules/.bin/tsx --no-cache scripts/ingest-manifests.mts
./node_modules/.bin/hardhat --config config/hardhat.config.js test --no-compile test/hardhat/placeholder.test.js
python3 -m unittest discover -s test/agents/ -p "test_*.py"
```

**Verified expected result**

- Manifest ingestion emits valid status with intact asset map.
- 83 Hardhat regression tests pass.
- 7 agent unit tests pass.
