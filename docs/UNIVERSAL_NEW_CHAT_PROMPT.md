# Universal New-Chat Prompt — Blockchain SOC Enterprise V10.3

Use this document whenever starting a new Perplexity session for the project.

Attach the current versions of:

1. `docs/CHECKLIST.md`
2. `docs/HANDOFF.md`
3. `docs/RUNBOOK.md`
4. `docs/UNIVERSAL_NEW_CHAT_PROMPT.md` — this document

Also provide the current repository tree and only the relevant **sanitized**
terminal, Git, GitLab CI, GitHub, source-code, configuration, test, error, and
diff output for the active task.

---

## Paste this prompt into every new chat

Brother, this is a continuation session for my long-running project:

**Autonomous AI-Native Blockchain Security Operations Center (SOC) — Enterprise V10.3.**

I have attached these authoritative project documents:

1. `docs/CHECKLIST.md`
   - The complete master implementation tracker.
   - It contains phases, task IDs, task names, statuses, evidence rules,
     dependencies, and phase-completion gates.

2. `docs/HANDOFF.md`
   - It contains the current project position, completed work, Git/CI state,
     blockers, constraints, and the **Immediate next task**.

3. `docs/RUNBOOK.md`
   - It is the operational guide for future users and operators.
   - It documents verified procedures for initializing, configuring, running,
     validating, stopping, recovering, and troubleshooting project components.
   - It must distinguish verified procedures from drafts, placeholders, and
     coursework simulations.

4. `docs/UNIVERSAL_NEW_CHAT_PROMPT.md`
   - It contains the required operating, safety, task-completion,
     phase-completion, continuity, documentation-update, runbook-maintenance,
     GitLab, and GitHub synchronization protocol.

I may also provide a repository tree, current Git status/log, GitLab pipeline
results, GitHub remote state, terminal output, source code, configuration files,
test files, errors, and diffs.

Read all four attached Markdown files completely before making recommendations,
selecting a task, proposing implementation changes, or generating commands.

---

# Source of truth and priority

Treat the following as authoritative, in this order:

1. Actual Kali Linux terminal output.
2. Actual source files, configuration files, Git diff, Git history, and
   repository state.
3. Actual GitLab CI/CD pipeline and job output.
4. Actual GitHub remote/branch/tag state, where provided.
5. `docs/CHECKLIST.md`.
6. `docs/HANDOFF.md`.
7. `docs/RUNBOOK.md`.
8. This prompt.

Do not assume access to prior Perplexity sessions unless the required facts are
present in the attached files or current conversation.

If evidence conflicts:

- Identify the contradiction clearly.
- Treat terminal output, repository state, Git history, and CI output as
  authoritative.
- Do not claim a task, test, CI job, deployment, remote push, synchronization,
  runbook procedure, or phase is complete until the contradiction is resolved.

---

# Automatic task selection

Do not require me to remember or manually provide a task ID or task name.

1. Read the `## Immediate next task` section in `docs/HANDOFF.md`.
2. Cross-check the task against its relevant entry in `docs/CHECKLIST.md`.
3. Confirm that dependencies are complete, verified, or explicitly documented
   as permitted coursework simulations.
4. Identify the active task exactly in this form:

   ```text
   Active task: [TASK-ID] — [exact task title]
   Current phase: Phase [N] — [phase name]
   ```

5. Before implementation, state all of the following:

   - Exact task ID and title.
   - Current phase.
   - Scope.
   - Explicitly out-of-scope work.
   - Expected files to create or modify.
   - Acceptance criteria.
   - Required validation commands.
   - Dependencies and blockers.
   - Whether the runbook is expected to change and why.
   - Current phase-gate status: incomplete, blocked, or complete and verified.

6. If `HANDOFF.md` does not have an Immediate next task, select the smallest
   unblocked, unchecked task in `CHECKLIST.md`, explain why it is next, and
   prepare the required `HANDOFF.md` update.

7. If the selected task is blocked, do not begin unrelated work. State the
   blocker and select only the smallest task that can legitimately remove it.

---

# Scope discipline

- Work only on the selected active task.
- Do not silently begin another task, phase, refactor, deployment, scan, or
  architecture redesign.
- If a requested action expands scope, explain why and ask for confirmation
  before changing scope.
- Prefer small, testable changes with exact file paths and explicit validation.
- Do not claim implementation, command, test, scan, CI job, Git operation,
  security control, deployment, remote push, synchronization, or runbook
  procedure succeeded unless factual evidence has been provided.

## Task evidence status and publication status


Task evidence status and repository-publication status are related but distinct.
Use both fields in task completion records, tracker notes, and handoff records
whenever a documentation/evidence commit is awaiting or has completed the
GitLab-first/GitHub-second publication workflow.


### Task evidence status


A checklist item can be marked `✅ Complete and verified` only when all
applicable requirements exist:

1. Approved implementation, configuration, or explicitly documented coursework
   simulation is complete.
2. Required command, test, scan, drill, CI job, or factual verification evidence
   has been collected successfully.
3. Required policy/security validation has been completed where relevant.
4. Factual evidence/results and limitations are recorded in
   `docs/CHECKLIST.md`.
5. Required documentation status surfaces are reconciled in `CHECKLIST.md`,
   `HANDOFF.md`, and applicable `RUNBOOK.md`.
6. A local Git evidence/documentation commit has been created.
7. If the task created or changed a user-executable operational procedure, the
   corresponding verified `docs/RUNBOOK.md` update has been completed.


### Publication status


Record publication separately for the exact evidence/documentation commit:

- `Pending publication`: The local evidence/documentation commit exists but has
  not yet completed GitLab CI, GitHub publication, or final SHA verification.
- `Published and verified`: The exact commit was pushed to GitLab `main`,
  required GitLab CI passed, the same commit was pushed to GitHub
  `origin/main`, and fetched `main`, `gitlab/main`, and `origin/main` resolve
  to the same full SHA.
- `Blocked`: State the exact failed or unverified publication step and do not
  claim synchronization.


### Timing rule for completion records


Do not write future GitLab CI, GitHub-post, or synchronization results into a
commit before those facts exist. A task may remain `🟧 Implemented but needs
verification` while its required local technical validation or documentation
reconciliation is incomplete.


After the evidence/documentation commit has successfully completed the
GitLab-first/GitHub-second workflow, update the task's tracker and handoff
status to `✅ Complete and verified` at the next normal documentation update.
Do not create a status-only commit solely to repeat a known successful
publication result unless a factual correction, active-task transition, or other
required documentation change already justifies that commit.


When the publication result is available after the evidence commit, record it
factually in the completion record, next task's handoff update, or other
normal documentation update. The update must name the evidence commit SHA and
state whether GitLab CI, GitHub publication, and three-way SHA synchronization
were verified.


Use only these task statuses:

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

# Mandatory documentation reconciliation gate


Documentation is a required task-completion control, not a final editorial
cleanup step. Before staging any task-completion, implementation, runbook, or
documentation-update commit, reconcile every applicable status surface across
the tracked project documents.


## State-model definitions


Use these terms only with the meanings below:


| Term | Permitted only when |
|---|---|
| `✅ Complete` | The approved in-scope task work is finished. |
| `✅ Verified` | Required acceptance checks were actually run successfully and factual results are recorded. |
| `Passed` | A named command, test, scanner, CI job, or pipeline returned success. Name the evidence. |
| `Committed` | A local Git commit exists. Record its SHA only after the commit succeeds. |
| `Published to GitLab` | The exact local commit was successfully pushed to the existing GitLab remote. |
| `GitLab CI passed` | GitLab reports successful CI/pipeline evidence for the exact published commit. |
| `Published to GitHub` | The same GitLab-gated commit was successfully pushed to `origin/main`. |
| `Synchronized` | After fetching both remotes, `main`, `gitlab/main`, and `origin/main` resolve to the same full SHA. |


Do not use `✅`, `complete`, `verified`, `passed`, `green`, `committed`,
`published`, or `synchronized` prospectively. Never present an expected commit,
pipeline outcome, remote push, or SHA equality as though it has already
occurred.


## Required reconciliation inventory


For the active task and any immediately preceding task whose status is edited,
inspect and reconcile every applicable surface:


- `docs/CHECKLIST.md`
  - Phase dashboard/tracker row.
  - Detailed task status.
  - Every acceptance-criteria checkbox.
  - Evidence, limitations, dependencies, and next-task wording.
- `docs/HANDOFF.md`
  - Current position table.
  - Current thread text.
  - Completed-since-previous-handoff record.
  - Detailed task record.
  - Immediate next task section and task queue.
  - Earlier task sections that still say `Current`, `pending`, `next`,
    `not run`, `not started`, or have stale unchecked criteria.
- `docs/RUNBOOK.md`
  - Applicable procedure status label.
  - Only factual commands, outcomes, and limitations that were actually
    verified.
- Any task-specific tracked README, CI configuration, evidence index, or
  operational record changed by the task.


A task may be marked `✅ Complete and verified` only when all applicable
required acceptance criteria are checked, the documentation surfaces agree with
the factual evidence, the required Git/GitLab/GitHub publication conditions in
this prompt have been met, and no unexplained stale state remains.


## Required pre-stage reconciliation checks


After updating the documents but before any `git add`, run:


```bash
git diff --check


git diff --name-only


git --no-pager diff --   docs/CHECKLIST.md   docs/HANDOFF.md   docs/RUNBOOK.md   docs/UNIVERSAL_NEW_CHAT_PROMPT.md


grep -RInE   --include='CHECKLIST.md'   --include='HANDOFF.md'   --include='RUNBOOK.md'   --include='UNIVERSAL_NEW_CHAT_PROMPT.md'   '(P[0-9]{2}-[0-9]{3}|Current task|Current thread|Status:|✅|\[ \]|pending|not run|not started|next task|TODO)'   docs
```


Manually inspect the output for the active task ID and related predecessor
records. Explain every remaining unchecked box or retained word such as
`pending`, `optional`, `not run`, `not started`, `deferred`, or `draft`.


Do not stage or commit until all applicable conditions are true:


1. Every required acceptance criterion is `[x]`; otherwise the task is not
   `✅ Complete and verified`.
2. The CHECKLIST tracker row, detailed task section, HANDOFF record, and
   applicable RUNBOOK procedure use the same factual state.
3. `HANDOFF.md` identifies the actual current task and the preceding completed
   task is not still presented as current.
4. No stale text says documentation, CI, publication, or synchronization is
   pending after that event has already occurred.
5. `git diff --check` passes.
6. The exact diff is reviewed before staging.
7. A secret-safety review of the changed tracked files passes.
8. `docs/.backup/` and other local recovery material remain untracked and are
   not staged.


Before proposing the local commit, provide a factual documentation-reconciliation
record containing:


- Active task ID and final state.
- Scope completed and scope intentionally not completed.
- Acceptance criteria: checked, deferred, failed, or not applicable.
- CHECKLIST tracker/detailed-task alignment result.
- HANDOFF current-position/current-task/historical-record alignment result.
- RUNBOOK alignment result or explicit reason it is not applicable.
- Commands run and factual results.
- Remaining limitations, deferred work, and optional follow-ups.
- Exact changed-file list and intended commit scope.


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
- Restrict PoCs, exploit validation, chain-monitoring tests, and network drills
  to local fixtures, controlled testnets, local Anvil forks, throwaway systems,
  and systems I own or am explicitly authorized to test.
- Label local validators, testnets, containers, fixtures, HSM emulators,
  simplified cryptography, simplified ZK circuits, mocked services, and other
  non-production components as `🔒 Coursework simulation`.
- Never describe a coursework simulation as a production deployment.
- Zone 9 reports may contain only sanitized/redacted summaries. Never include
  raw sealed evidence, private keys, key shares, raw credentials, or unredacted
  compliance reports.
- Do not add unverified operational commands to `docs/RUNBOOK.md`. Clearly mark
  any untested procedure as `Draft`, `Placeholder`, or `Not yet verified`.

---

# Git, GitLab, and GitHub synchronization workflow

The local Kali repository is the development source of truth:

```text
~/Blockchain-Security-Project-Remastered
```

The normal working branch is:

```text
main
```

The repository must remain synchronized in all three locations:

```text
Local Kali repository
→ private GitLab repository and GitLab CI/CD
→ GitHub repository
```

The verified remote aliases and URLs are:

```text
gitlab
  GitLab fetch URL:
  gitlab-soc:root/blockchain-security-project-remastered.git

  GitLab push URL:
  gitlab-soc:root/blockchain-security-project-remastered.git

origin
  GitHub fetch URL:
  git@github.com:ali4210/Blockchain-Security-Project-Remastered.git

  GitHub push URL:
  git@github.com:ali4210/Blockchain-Security-Project-Remastered.git
```

At the start of a session, or whenever remote configuration is uncertain,
verify the configured URLs with:

```bash
git remote -v

# No --fetch flag exists; the fetch URL is the default.
git remote get-url gitlab
git remote get-url --push gitlab

git remote get-url origin
git remote get-url --push origin
```

Do not generate `git remote add`, `git remote set-url`, `git remote remove`,
or `git remote rename` commands unless I explicitly request a remote
configuration change.

For every successfully completed task, implementation, file addition, runbook
update, or accepted documentation update, use this exact synchronization
sequence:

```text
Edit locally in Kali
→ run factual local validation
→ update CHECKLIST.md and HANDOFF.md when task state changes
→ update RUNBOOK.md when verified user-operational procedure changes
→ review the intended Git diff
→ create a local Git commit
→ post/push the exact commit to GitLab main
→ wait for and verify the GitLab CI/CD pipeline result
→ post/push the same exact commit to GitHub origin main
→ fetch both remotes
→ prove that local main, gitlab/main, and origin/main have the same commit SHA
```

The final repository-posting requirement is mandatory. After every successful
local Git commit, the model must provide the first final posting command:

```bash
# Required final post 1: GitLab main.
git push gitlab main
```

GitLab is the CI/CD gate. After `git push gitlab main`, the model must stop and
ask for factual GitLab pipeline evidence. It must not claim that GitHub is
current yet.

Only after successful GitLab CI/CD evidence is provided, the model must provide
the second final posting command:

```bash
# Required final post 2: GitHub main.
git push origin main
```

After both final pushes, the model must require this exact synchronization
verification:

```bash
git fetch gitlab
git fetch origin

printf 'local main:  '
git rev-parse main

printf 'GitLab main: '
git rev-parse gitlab/main

printf 'GitHub main: '
git rev-parse origin/main

git log -1 --oneline
git status
```

The three commit hashes must be identical:

```text
main == gitlab/main == origin/main
```

Only then may the model state:

```text
The local Kali repository, GitLab main repository, and GitHub main repository
are synchronized at the same commit.
```

If a local commit, GitLab push, GitLab pipeline, GitHub push, fetch,
authentication operation, or commit-hash comparison fails:

1. Stop.
2. Do not use `git push --force`.
3. Do not claim a remote is synchronized unless the exact SHA comparison proves
   it.
4. Record the factual failure or blocker in `docs/HANDOFF.md`.
5. State only the smallest safe remediation step.
6. Do not begin unrelated work until the synchronization failure is resolved or
   explicitly recorded as an accepted blocker.

Never use `git push --force`. Use `git push --force-with-lease` only if I
explicitly request a history rewrite after supplying factual evidence and after
the risk has been recorded in `docs/HANDOFF.md`.

For verified phase completion, first synchronize the phase-completion commit to
both remotes. Only then create and push the same annotated phase tag to both
remote repositories:

```bash
git tag -a vX.Y.Z-phase-NN \
  -m "Phase NN [phase name] verified"

git push gitlab vX.Y.Z-phase-NN
git push origin vX.Y.Z-phase-NN

git ls-remote --tags gitlab vX.Y.Z-phase-NN
git ls-remote --tags origin vX.Y.Z-phase-NN
```

Do not edit tracked project files through GitLab or GitHub web interfaces unless
I explicitly request it. If a remote-web edit occurs, require a fetch,
divergence check, and safe reconciliation before additional local work.

---

# Runbook maintenance requirements

`docs/RUNBOOK.md` is the authoritative operational guide for future users and
operators of this project. It is distinct from:

- `docs/CHECKLIST.md`, which tracks implementation completion, task evidence,
  dependencies, and phase gates.
- `docs/HANDOFF.md`, which records current-session continuity, project state,
  blockers, and the immediate next task.
- `docs/UNIVERSAL_NEW_CHAT_PROMPT.md`, which governs how future AI sessions
  operate.

Update `docs/RUNBOOK.md` only when the active task creates, changes, verifies,
deprecates, or materially affects a user-executable operational procedure,
including:

- environment bootstrap;
- dependency installation;
- local configuration;
- startup or shutdown;
- health checks;
- local validation;
- test execution;
- CI/CD operation;
- evidence-safe collection;
- backup or recovery;
- troubleshooting;
- rollback;
- role/approval workflow; or
- GitLab/GitHub synchronization.

Do not update `RUNBOOK.md` merely to repeat a checklist status or a temporary
chat/session detail.

For every runbook update, provide:

1. Procedure title and purpose.
2. Scope and explicit limitations.
3. Preconditions and safety boundaries.
4. Exact tested commands.
5. Expected successful results.
6. Failure indicators.
7. Safe troubleshooting, cleanup, rollback, or escalation.
8. Coursework-simulation limitations.
9. Factual evidence/verification details.
10. Associated task ID and relevant source/configuration paths.

Never invent commands, environment values, port numbers, service names,
credentials, policy decisions, or deployment details. Do not label a procedure
as verified unless factual execution evidence has been provided.

Use one of these labels for each runbook procedure:

```text
✅ Verified
🟧 Implemented but needs verification
🟨 Draft / placeholder
🟪 Blocked
🔒 Coursework simulation
```

When a task changes `RUNBOOK.md`, include that file in the exact end-of-task
documentation-update, review, commit, GitLab push, GitLab CI check, GitHub
push, and three-way SHA verification workflow.

---

# Required automatic end-of-task protocol

At the end of **every active task**, after I provide factual terminal, Git,
test, scanner, GitLab CI, GitHub synchronization, and relevant operational
evidence, automatically perform all steps below. Do not wait for me to remember
or request them.

## 1. Determine factual task status

State exactly one of:

```text
✅ Complete
🟧 Needs verification
🟨 Stubbed / dependency pending
🟪 Blocked
```

Explain the decision using only factual evidence I provided.

Do not call a task `✅ Complete` if an applicable local validation, local
commit, GitLab push, GitLab CI requirement, GitHub push, three-way SHA
synchronization, or required runbook update is missing or unverified.

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
- GitLab and GitHub push/synchronization evidence, if available.
- Evidence/artifact paths, if available.
- Git commit hash, if available; otherwise clearly state `pending`.
- Security checks.
- Dependencies created, consumed, blocked, or deferred.
- Runbook impact: updated, not required, or deferred, with reason.
- Coursework simulations and limitations.
- Recommended next task.

Do not claim that a commit, remote push, CI pipeline, synchronization, or
runbook verification exists until I provide factual evidence.

## 3. Generate the `HANDOFF.md` update

Provide an exact ready-to-paste update block containing:

- Current phase and status.
- Completed-task summary.
- Latest verified commit.
- GitLab push and GitLab CI status, if provided.
- GitHub push status, if provided.
- Three-way commit-SHA synchronization status, if provided.
- Runbook update/verification status.
- Current blockers and risks.
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
- Whether `RUNBOOK.md` is expected to change and why.

This section is mandatory because the next Perplexity session uses it to
identify its task automatically.

## 4. Generate the `RUNBOOK.md` update when needed

Generate a `docs/RUNBOOK.md` update only when the active task creates, changes,
verifies, or deprecates an operational procedure that a future user needs to
execute.

When required, provide an exact ready-to-paste runbook update block containing:

- Procedure name.
- Status label: `✅ Verified`, `🟧 Implemented but needs verification`,
  `🟨 Draft / placeholder`, `🟪 Blocked`, or `🔒 Coursework simulation`.
- Purpose and scope.
- Preconditions.
- Safety boundaries.
- Exact commands that were actually tested.
- Expected results based only on factual evidence.
- Failure indicators.
- Safe troubleshooting, cleanup, rollback, or escalation.
- Evidence, associated task ID, and changed-file references.
- Limitations, including coursework-simulation limitations.

If no runbook change is needed, explicitly state:

```text
RUNBOOK.md update: Not required.
Reason: [specific reason].
```

Never insert guessed or untested commands into the runbook.

## 5. Generate safe automated Markdown update commands

After providing the Markdown update blocks, provide **one self-contained,
copy-pasteable Python 3 standard-library command for each Markdown file that
changes**:

```text
docs/CHECKLIST.md
docs/HANDOFF.md
docs/RUNBOOK.md
```

Normally, a completed, blocked, or materially updated task changes both
`CHECKLIST.md` and `HANDOFF.md`.

Update `RUNBOOK.md` only when a verified or materially changed operational
procedure requires it. If only some files should change, generate commands only
for those files and explain why. Never update files that I did not explicitly
approve as changed.

For each file-update command, the command must:

1. Be runnable from the repository root.
2. Use only the Python 3 standard library.
3. Read the target file as UTF-8.
4. Create a timestamped backup under:

   ```text
   docs/.backup/
   ```

5. Define a complete, exact, unique `old` block and a complete `new` block.
6. Verify that the exact `old` block appears **exactly once**.
7. Abort without changing anything if:
   - the target file is missing;
   - the old block is absent;
   - the old block appears more than once; or
   - any unexpected replacement count occurs.
8. Write atomically through a temporary file in the same directory, then replace
   the original file.
9. Print the target file path, backup path, and confirmation of one replacement.
10. Never include, print, or persist secrets, private keys, tokens, raw
    evidence, or unredacted compliance data.
11. Never use broad or unscoped replacement, such as:

    ```python
    text.replace("✅", "⬜")
    ```

    or a generic phrase replacement that is not based on one complete, unique
    old block.

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

After all generated Python document-update commands, always provide mandatory
review commands that list only the files that actually changed. For example:

```bash
git diff --check
git diff -- docs/CHECKLIST.md docs/HANDOFF.md docs/RUNBOOK.md
```

If `RUNBOOK.md` was not changed, omit it from the second command.

## 6. Generate Git review, commit, GitLab post, and GitHub post commands

For every accepted task, file completion, implementation change, runbook update,
or documentation update, generate exact commands using only known intended
changed files:

```bash
git status
git diff --check
git diff -- [changed paths]

git add [only intended paths]
git diff --cached --check
git diff --cached

git commit -m "[accurate conventional commit message]"
```

After a successful local Git commit, the model must provide the first required
final repository-posting command:

```bash
# Required final post 1: GitLab main.
git push gitlab main
```

Then stop and instruct me to wait for factual successful GitLab CI/CD pipeline
evidence.

Only after I provide GitLab CI/CD success, the model must provide:

```bash
# Required final post 2: GitHub main.
git push origin main
```

Then the model must require and evaluate this synchronization verification:

```bash
git fetch gitlab
git fetch origin

printf 'local main:  '
git rev-parse main

printf 'GitLab main: '
git rev-parse gitlab/main

printf 'GitHub main: '
git rev-parse origin/main

git log -1 --oneline
git status
```

Do not report a task as fully synchronized until:

```text
main == gitlab/main == origin/main
```

The end-of-task response must explicitly state one of these outcomes:

```text
✅ Local, GitLab main, and GitHub main are synchronized at [commit SHA].
```

or:

```text
🟪 Synchronization is incomplete.
Failed or unverified step: [exact step].
Do not begin unrelated work until it is resolved or documented as a blocker.
```

## 7. Evaluate the active phase gate

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

- If every gate requirement has factual evidence, all required documentation is
  updated, and the completed phase commit is synchronized across local, GitLab,
  and GitHub, state:

  ```text
  Phase [N] is complete and verified.
  Do not begin Phase [N+1] in this thread.
  ```

## 8. Generate the next-session starter prompt

If the phase is incomplete, automatically provide a complete starter prompt for
the Immediate next task. It must include:

- Project name.
- The four authoritative documents to attach.
- Active next task ID and title.
- Scope and explicit out-of-scope work.
- Expected files.
- Acceptance criteria.
- Validation commands.
- Dependencies and blockers.
- Required security rules.
- Whether `RUNBOOK.md` is expected to change and why.
- Reminder to update `CHECKLIST.md` and `HANDOFF.md` when task state changes.
- Reminder to update `RUNBOOK.md` only for verified operational-procedure
  changes.
- Reminder to run generated safe Python update commands.
- Reminder to review the Git diff.
- Reminder to commit locally.
- Reminder to post/push to GitLab `main`.
- Reminder to wait for successful GitLab CI.
- Reminder to post/push the same commit to GitHub `origin/main`.
- Reminder to verify that local `main`, `gitlab/main`, and `origin/main` have
  identical commit SHA values.

I should be able to start a new session, attach the four Markdown files, paste
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
   - `RUNBOOK.md`, if the completed phase created, changed, verified, or
     deprecated user-operational procedures.

3. Generate safe Python replacement commands for every Markdown document that
   changes, using the exact-one-match, backup, and atomic-write rules above.

4. Provide a phase-completion record including:

   - All verified gate criteria.
   - Tests, scans, CI jobs, drills, and command evidence.
   - Commit hash.
   - GitLab push and GitLab CI pipeline status.
   - GitHub push status.
   - Proof that local `main`, `gitlab/main`, and `origin/main` are synchronized.
   - Runbook procedures created or updated, if applicable.
   - Coursework simulations and limitations.
   - Open risks and dependencies.
   - Proposed annotated Git tag.

5. Provide Git commands to commit and push the phase documentation, using only
   the documentation files that actually changed. For example:

   ```bash
   git add docs/CHECKLIST.md docs/HANDOFF.md docs/RUNBOOK.md
   git diff --cached --check
   git diff --cached

   git commit -m "docs(phase-NN): verify [phase name] completion gate"

   git push gitlab main
   ```

6. Require factual successful GitLab CI/CD evidence. Then provide:

   ```bash
   git push origin main

   git fetch gitlab
   git fetch origin

   git rev-parse main
   git rev-parse gitlab/main
   git rev-parse origin/main
   ```

7. Require all three commit hashes to match. Only then provide the annotated tag
   commands:

   ```bash
   git tag -a vX.Y.Z-phase-NN \
     -m "Phase NN [phase name] verified"

   git push gitlab vX.Y.Z-phase-NN
   git push origin vX.Y.Z-phase-NN

   git ls-remote --tags gitlab vX.Y.Z-phase-NN
   git ls-remote --tags origin vX.Y.Z-phase-NN
   ```

8. Require confirmation that the phase commit and phase tag exist on both
   GitLab and GitHub before telling me to open the next Perplexity session.

9. Generate the complete starter prompt for the first task of the next phase.

---

# Required response format

Before implementation, provide:

1. Active task ID and exact title.
2. Current phase.
3. Scope and out-of-scope work.
4. Expected changed files.
5. Whether `RUNBOOK.md` is expected to change and why.
6. Acceptance criteria.
7. Validation commands.
8. Dependencies and blockers.
9. Current phase-gate status.

After I provide factual evidence, provide:

1. Task-status decision.
2. Exact `CHECKLIST.md` update block.
3. Exact `HANDOFF.md` update block.
4. Exact `RUNBOOK.md` update block when required, or an explicit statement that
   it is not required and why.
5. One safe Python update command for each changed Markdown file.
6. Mandatory Git diff review commands.
7. Exact Git review and local commit commands, with one recommended commit
   message.
8. Required first final post command: `git push gitlab main`.
9. Instruction to wait for factual GitLab CI/CD result.
10. Required second final post command after CI success:
    `git push origin main`.
11. Exact three-way SHA synchronization commands.
12. Explicit synchronization result: complete or incomplete.
13. Phase-gate evaluation.
14. Immediate next task.
15. Full starter prompt for the next session.

Wait for real terminal, Git, test, scanner, GitLab CI, GitHub push, fetch,
commit-SHA, and relevant operational-procedure evidence before claiming that
any task, test, pipeline, synchronization, runbook procedure, or phase has
passed or is complete.

---

# Minimal message for future sessions

After attaching the four files above, paste this short message:

```text
Brother, read the attached CHECKLIST.md, HANDOFF.md, RUNBOOK.md, and
UNIVERSAL_NEW_CHAT_PROMPT.md completely.

Here is the current repository tree and any relevant sanitized terminal, Git,
GitLab CI, GitHub, source, configuration, test, error, or diff output.

Proceed with the Immediate next task in HANDOFF.md. First identify the active
task, scope, out-of-scope work, expected files, whether RUNBOOK.md must change,
acceptance criteria, validation commands, dependencies, blockers, and current
phase-gate status. Do not start implementation until you state them.

For any accepted task completion, update CHECKLIST.md and HANDOFF.md as needed.
Update RUNBOOK.md only for verified user-operational procedure changes. Review
the diff, commit locally, push to GitLab main, wait for GitLab CI success, push
the same commit to GitHub origin main, and verify that main, gitlab/main, and
origin/main have the identical commit SHA.
```