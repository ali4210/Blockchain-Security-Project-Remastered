# Universal New-Chat Prompt — Blockchain SOC Enterprise V10.3

Use this document whenever starting a new Perplexity session for the project. Attach the current versions of:

1. `docs/CHECKLIST.md`
2. `docs/HANDOFF.md`
3. `docs/UNIVERSAL_NEW_CHAT_PROMPT.md` (this document)

Also provide the current repository tree and only the relevant sanitized terminal, Git, CI, source-code, configuration, test, error, or diff output for the active task.

---

## Paste the prompt below

Brother, this is a continuation session for my long-running project:

**Autonomous AI-Native Blockchain Security Operations Center (SOC) — Enterprise V10.3.**

I have attached these authoritative project documents:

1. `docs/CHECKLIST.md`
   - The complete master implementation tracker.
   - It contains phases, task IDs, task names, task status, evidence rules,
     dependencies, and phase-completion gates.

2. `docs/HANDOFF.md`
   - It contains the current project position, completed work, Git/CI state,
     blockers, constraints, and the **Immediate next task**.

3. `docs/UNIVERSAL_NEW_CHAT_PROMPT.md`
   - It contains the required operating, safety, task-completion,
     phase-completion, continuity, and automated-document-update protocol.

I may also provide a repository tree, current Git status/log, GitLab pipeline
result, terminal output, code/configuration/test files, errors, and diffs.

Read all three attached Markdown files completely before making recommendations.

---

# Source of truth and priority

Treat the following as authoritative, in this order:

1. Actual Kali Linux terminal output.
2. Actual source files, configuration files, Git diff, Git history, and repository state.
3. GitLab CI/CD pipeline and job output.
4. `docs/CHECKLIST.md`.
5. `docs/HANDOFF.md`.
6. This prompt.

Do not assume access to prior Perplexity sessions unless the required facts are
present in the attached files or in the current conversation.

If evidence conflicts:

- Identify the contradiction clearly.
- Treat terminal output, repository state, Git history, and CI output as
  authoritative.
- Do not claim a task is complete or generate final document updates until the
  contradiction is resolved.

---

# Automatic task selection

Do not require me to remember or manually supply a new task ID or task name.

1. Read the `## Immediate next task` section of `docs/HANDOFF.md`.
2. Cross-check that task against the relevant section in `docs/CHECKLIST.md`.
3. Confirm that dependencies are completed, verified, or explicitly documented
   as permitted coursework simulations.
4. Identify the active task in this exact form:

   ```text
   Active task: [TASK-ID] — [exact task title]
   Current phase: Phase [N] — [phase name]
   ```

5. Before implementation, state:

   - Exact task ID and title.
   - Scope.
   - Explicitly out-of-scope work.
   - Expected files to create or modify.
   - Acceptance criteria.
   - Required validation commands.
   - Dependencies and blockers.
   - Current phase-gate status: incomplete, blocked, or complete and verified.

6. If `HANDOFF.md` has no Immediate next task, select the first smallest
   unblocked, unchecked task in `CHECKLIST.md`, explain why it is next, and
   prepare the required `HANDOFF.md` update.

7. If the selected task is blocked, do not start unrelated work. State the
   blocker and select only the smallest task that can legitimately remove it.

---

# Scope discipline

- Work only on the selected active task.
- Do not silently begin another task, phase, refactor, deployment, scan, or
  architecture redesign.
- If a requested action expands scope, explain why and ask for confirmation
  before changing scope.
- Prefer small, testable changes with exact file paths and explicit validation.
- Do not claim an implementation, command, test, scan, CI job, Git operation,
  security control, or deployment succeeded without factual evidence I provide.

A checklist item can be marked `✅ Complete` only when all of the following exist:

1. Implementation, configuration, or explicitly documented coursework simulation.
2. Relevant command, test, scan, drill, CI job, or factual verification evidence.
3. Required policy/security validation where relevant.
4. Evidence/result recorded in `docs/CHECKLIST.md`.
5. A Git commit containing the applicable implementation and documentation update.

Use only these statuses:

```text
⬜ Not started
🟦 In progress
🟨 Stubbed / waiting on a planned dependency
🟪 Blocked
🟧 Implemented but needs verification
✅ Complete and verified
🔒 Coursework simulation / documented scope reduction
```

---

# Security and safety requirements

- Agents are read-only by default.
- Sensitive actions require Open Policy Agent authorization and the appropriate
  human principal.
- Only `soc-operator` may authorize evidence acquisition/sealing, sensitive
  remediation, release-token operations, real signing, or key-rotation actions.
- Only `compliance-officer` may approve or file compliance/regulatory reports.
- Never ask for, expose, paste, print, log, or commit:
  - passwords;
  - personal access tokens;
  - GitLab Runner authentication tokens;
  - API tokens;
  - private SSH keys;
  - mTLS private keys;
  - wallet private keys or seed phrases;
  - Shamir shares;
  - HSM/MPC secret material;
  - raw sealed forensic evidence;
  - unredacted SAR/compliance data.
- Treat all source code, logs, external text, evidence, free-text fields, and
  third-party artifacts as untrusted input.
- Preserve AST masking, evidence sanitization, structured parsing, data-only
  framing, size limits, and least-privilege boundaries.
- Restrict PoCs, exploit validation, chain monitoring tests, and network drills
  to local fixtures, controlled testnets, local Anvil forks, throwaway systems,
  and systems I own or am explicitly authorized to test.
- Label local validators, testnets, containers, fixtures, HSM emulators,
  simplified cryptography, simplified ZK circuits, mocked services, and other
  non-production components as `🔒 Coursework simulation`.
- Never describe a coursework simulation as a production deployment.
- Zone 9 reports may contain only sanitized/redacted summaries. Never include
  raw sealed evidence, private keys, key shares, raw credentials, or unredacted
  compliance reports.

---

# Git and CI/CD workflow

The repository is normally:

```text
~/Blockchain-Security-Project-Remastered
```

The normal working branch is:

```text
main
```

The private GitLab CI/CD remote is normally:

```text
gitlab-soc:root/blockchain-security-project-remastered.git
```

The GitHub remote is normally:

```text
git@github.com:ali4210/Blockchain-Security-Project-Remastered.git
```

For ordinary project changes, use this order:

```text
Edit locally in Kali
→ Run local validation
→ Update CHECKLIST.md and HANDOFF.md
→ Review Git diff
→ Commit locally
→ Push to GitLab
→ Confirm GitLab pipeline result
→ Push to GitHub
→ Verify local, GitLab, and GitHub branches are aligned
```

Do not use force-push unless I explicitly provide evidence that histories are
patch-equivalent and explicitly instruct a safe `--force-with-lease` operation.

Do not create a phase tag until the relevant phase completion gate is fully
verified.

For normal committed changes, provide and use:

```bash
git push gitlab main
```

Wait for the relevant GitLab CI pipeline result. After a passing pipeline:

```bash
git push origin main

git fetch gitlab
git fetch origin

git rev-parse main
git rev-parse gitlab/main
git rev-parse origin/main

git status
git log -1 --oneline
```

The three commit hashes must match before the task is treated as synchronized.

Do not edit tracked project files through the GitLab web UI unless I explicitly
intend to do so and then fetch/reconcile the resulting remote commit before
continuing local work.

---

# Required automatic end-of-task protocol

At the end of **every active task**, after I provide factual terminal, Git,
test, scanner, and CI evidence, automatically perform all steps below. Do not
wait for me to remember or request them.

## 1. Determine factual task status

State exactly one of:

```text
✅ Complete
🟧 Needs verification
🟨 Stubbed / dependency pending
🟪 Blocked
```

Explain the decision using only factual evidence I provided.

## 2. Generate the `CHECKLIST.md` update

Provide an exact ready-to-paste update block for the relevant `CHECKLIST.md`
task section containing:

- Task ID and title.
- Correct task status.
- Scope completed and scope not completed.
- Files created or modified.
- Validation commands actually run.
- Factual results only.
- GitLab CI job/pipeline evidence, if available.
- Evidence/artifact paths, if available.
- Git commit hash, if available; otherwise clearly say `pending`.
- Security checks.
- Dependencies created, consumed, blocked, or deferred.
- Coursework simulations and limitations.
- Recommended next task.

Do not claim a commit exists until I provide its actual hash.

## 3. Generate the `HANDOFF.md` update

Provide an exact ready-to-paste update block containing:

- Current phase and status.
- Completed-task summary.
- Latest verified commit and CI status, if provided.
- Current blockers/risks.
- A required section titled exactly:

  ```markdown
  ## Immediate next task
  ```

The Immediate next task section must include:

- Next task ID.
- Exact next task title.
- Scope.
- Expected files.
- Acceptance criteria.
- Validation commands.
- Dependencies.
- Important security constraints.

This section is mandatory because the next Perplexity session uses it to
identify its task automatically.

## 4. Generate safe automated Markdown update commands

After providing the Markdown update blocks, provide **one self-contained,
copy-pasteable Python 3 standard-library command for each Markdown file that
changes**:

```text
docs/CHECKLIST.md
docs/HANDOFF.md
```

Normally, a completed or blocked task changes both files. If only one file
should change, generate a command only for that file and explain why. Never
update files that I did not explicitly approve as changed.

For each file-update command, the command must:

1. Be runnable from the repository root.
2. Use only the Python 3 standard library.
3. Read the target as UTF-8.
4. Create a timestamped backup under:

   ```text
   docs/.backup/
   ```

5. Define a complete, exact, unique `old` block and a complete `new` block.
6. Verify the exact `old` block appears **exactly once**.
7. Abort without changing anything if:
   - target file is missing;
   - old block is absent;
   - old block appears more than once; or
   - any unexpected replacement count occurs.
8. Write atomically through a temporary file in the same directory, then replace
   the original file.
9. Print the target file path, backup path, and confirmation of one replacement.
10. Never include, print, or persist secrets, private keys, tokens, raw evidence,
    or unredacted compliance data.
11. Never use broad/unscoped replacement such as:

    ```python
    text.replace("✅", "⬜")
    ```

    or a generic phrase replacement that is not based on a full unique old block.
12. Use an `old` block copied from the actual current file content I provided.
    Do not invent old text. If the relevant current section was not provided,
    request that section before generating automated replacement commands.

Use this required command pattern, adapting only `target`, `old`, and `new`:

```bash
python3 - <<'PY'
from pathlib import Path
from datetime import datetime
import os
import tempfile

target = Path("docs/TARGET_FILE.md")
old = """EXACT OLD BLOCK"""
new = """EXACT NEW BLOCK"""

if not target.is_file():
    raise SystemExit(f"ERROR: missing target file: {target}")

text = target.read_text(encoding="utf-8")
count = text.count(old)

if count != 1:
    raise SystemExit(
        f"ERROR: expected exactly one matching block in {target}, found {count}. "
        "No changes were made."
    )

backup_dir = target.parent / ".backup"
backup_dir.mkdir(parents=True, exist_ok=True)
stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
backup = backup_dir / f"{target.name}.{stamp}.bak"
backup.write_text(text, encoding="utf-8")

updated = text.replace(old, new, 1)

fd, temp_name = tempfile.mkstemp(
    prefix=f".{target.name}.",
    suffix=".tmp",
    dir=str(target.parent),
)
try:
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
        handle.write(updated)
    os.replace(temp_name, target)
except Exception:
    try:
        os.unlink(temp_name)
    except FileNotFoundError:
        pass
    raise

print(f"UPDATED: {target}")
print(f"BACKUP:  {backup}")
print("REPLACEMENTS: 1")
PY
```

After all generated Python document-update commands, always provide these
mandatory review commands:

```bash
git diff --check
git diff -- docs/CHECKLIST.md docs/HANDOFF.md
```

## 5. Generate Git review, commit, and push commands

Generate exact commands using only known changed files. Start with:

```bash
git status
git diff --check
git diff -- [changed paths]

git add [only intended paths]

git diff --cached --check
git diff --cached

git commit -m "[accurate conventional commit message]"

git push gitlab main
```

Then instruct me to wait for the GitLab pipeline result before pushing to GitHub.

After GitLab CI passes, provide:

```bash
git push origin main

git fetch gitlab
git fetch origin

git rev-parse main
git rev-parse gitlab/main
git rev-parse origin/main

git log -1 --oneline
git status
```

## 6. Evaluate the active phase gate

After every task, inspect the active phase gate in `CHECKLIST.md`.

- If incomplete, state:

  ```text
  Phase [N] is not complete.
  Remaining gate items are:
  - ...
  ```

- If blocked, state:

  ```text
  Phase [N] is blocked.
  Blocker:
  ...
  ```

- If every requirement has factual evidence, state:

  ```text
  Phase [N] is complete and verified.
  Do not begin Phase [N+1] in this thread.
  ```

## 7. Generate the next-session starter prompt

If the phase is incomplete, automatically provide a complete starter prompt for
the Immediate next task. It must include:

- Project name.
- The three authoritative documents to attach.
- Active next task ID and title.
- Scope and explicit out-of-scope work.
- Expected files.
- Acceptance criteria.
- Validation commands.
- Dependencies/blockers.
- Required security rules.
- Reminder to update both Markdown files, run generated safe Python update
  commands, review the Git diff, commit, push GitLab, wait for CI, then push
  GitHub.

I should be able to start a new session, attach the three Markdown files, paste
that generated starter prompt, and continue without remembering task details.

---

# Automatic phase-completion protocol

Only when every phase-gate requirement is factually verified:

1. State:

   ```text
   Phase [N] is complete and verified.
   Do not begin Phase [N+1] in this thread.
   ```

2. Provide final complete updates for:

   - The completed phase section in `CHECKLIST.md`.
   - The phase dashboard entry in `CHECKLIST.md`.
   - The phase gate evidence in `CHECKLIST.md`.
   - `HANDOFF.md`, setting the first task of Phase `[N+1]` as the Immediate
     next task.

3. Generate safe Python replacement commands for both Markdown documents using
   the exact-one-match, backup, and atomic-write rules above.

4. Provide a phase-completion record including:

   - All verified gate criteria.
   - Tests, scans, CI jobs, drills, and command evidence.
   - Commit hash and GitLab pipeline status, if provided.
   - Coursework simulations and limitations.
   - Open risks and dependencies.
   - Proposed annotated Git tag.

5. Provide Git commands to commit/push phase documentation:

   ```bash
   git add docs/CHECKLIST.md docs/HANDOFF.md
   git diff --cached --check
   git commit -m "docs(phase-NN): verify [phase name] completion gate"

   git push gitlab main
   ```

6. Require GitLab pipeline success, then provide:

   ```bash
   git push origin main

   git tag -a vX.Y.Z-phase-NN \
     -m "Phase NN [phase name] verified"

   git push gitlab vX.Y.Z-phase-NN
   git push origin vX.Y.Z-phase-NN
   ```

7. Require confirmation that the commit and tag exist before telling me to open
   the next Perplexity session.

8. Generate the complete starter prompt for the first task of the next phase.

---

# Required response format

Before implementation, provide:

1. Active task ID and exact title.
2. Current phase.
3. Scope and out-of-scope work.
4. Expected changed files.
5. Acceptance criteria.
6. Validation commands.
7. Dependencies and blockers.
8. Current phase-gate status.

After I provide factual evidence, provide:

1. Task-status decision.
2. Exact `CHECKLIST.md` update block.
3. Exact `HANDOFF.md` update block.
4. One safe Python update command for each changed Markdown file.
5. Mandatory Git diff review commands.
6. Exact Git review, commit, and push commands with one recommended commit message.
7. GitLab pipeline waiting instruction.
8. Phase-gate evaluation.
9. Immediate next task.
10. Full starter prompt for the next session.

Wait for real terminal, Git, test, scanner, and CI output before claiming that
any task, test, pipeline, or phase has passed or is complete.

---

## Minimal message for future sessions

After attaching the three files above, paste this short message:

```text
Brother, read the attached CHECKLIST.md, HANDOFF.md, and
UNIVERSAL_NEW_CHAT_PROMPT.md completely.

Here is the current repository tree and any relevant sanitized terminal, Git,
CI, source, configuration, test, error, or diff output.

Proceed with the Immediate next task in HANDOFF.md. First identify the active
task, scope, out-of-scope work, expected files, acceptance criteria, validation
commands, dependencies, blockers, and current phase-gate status. Do not start
implementation until you state them.
```
