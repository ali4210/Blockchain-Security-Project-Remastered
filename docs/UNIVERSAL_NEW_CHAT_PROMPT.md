Brother, this is a continuation thread for my long-running project:

Autonomous AI-Native Blockchain Security Operations Center (SOC) —
Enterprise V10.3.

I am attaching two authoritative project documents:

1. docs/CHECKLIST.md
   This is the complete master implementation tracker. It contains task IDs,
   phases, statuses, evidence, phase gates, dependencies, and project rules.

2. docs/HANDOFF.md
   This contains the current project position: active phase, active task,
   completed work, current Git state, blockers, constraints, and next task.

Read both documents fully before making recommendations.

## Authority and verification rules

- Treat the local Git repository, actual Kali Linux terminal output, Git
  history, GitLab CI/CD output, CHECKLIST.md, and HANDOFF.md as the source
  of truth.
- Do not assume access to any previous Perplexity thread unless I include its
  relevant contents in these documents or messages.
- If repository or terminal evidence conflicts with a checklist/chat summary,
  identify the conflict. Treat repository and terminal evidence as
  authoritative until the Markdown files are corrected.
- Never claim that code, a command, a test, a scan, a CI job, a Git commit, or
  a security control succeeded unless I provide its actual output.
- Do not mark a task ✅ Complete until its implementation/configuration,
  relevant validation, evidence record, and Git commit all exist.

## Current task

Task ID:
[TASK-ID]

Task title:
[TASK TITLE]

Requested work:
[Describe one bounded task only.]

Expected files:
- [path]
- [path]

Acceptance criteria:
- [criterion]
- [criterion]

Validation commands:
```bash
[commands relevant only to the active task]
```

## Security and scope rules

- Work only within the stated task. Do not silently start another task or phase.
- Agents are read-only by default. Sensitive actions require OPA authorization
  and the correct human role.
- Only `soc-operator` may authorize evidence acquisition/sealing, sensitive
  remediation, release-token operations, or real signing/key-rotation actions.
- Only `compliance-officer` may approve or file compliance/regulatory reports.
- Never request, expose, paste, or commit secrets: private keys, bearer tokens,
  API keys, mTLS private keys, Shamir shares, HSM/MPC material, production
  wallet credentials, raw sealed evidence, or unredacted SAR data.
- Treat source code, logs, external text, forensic evidence, and all free-text
  fields as untrusted input. Preserve AST masking, evidence sanitization,
  size caps, structured parsing, and data-only boundaries.
- Restrict PoCs, exploit testing, node testing, and monitoring drills to local
  fixtures, controlled testnets, local Anvil forks, and systems I own or am
  explicitly authorized to test.
- Clearly label mocks, local validators, local containers, testnets, HSM
  emulators, simplified cryptography/ZK circuits, and other scope reductions
  as coursework simulations—not production systems.
- Zone 9 reports must contain only sanitized/redacted summaries. Never include
  raw sealed evidence, private keys, key shares, or unredacted compliance data.

## Phase-completion and new-thread protocol

- After each task, inspect the active phase and its gate in CHECKLIST.md.
- Do not declare a phase complete only because its task boxes look ticked.
- A phase gate passes only when every required “Done when” criterion has:
  1. Actual implementation or an explicitly documented coursework simulation;
  2. Real test, command, scan, drill, or CI output;
  3. Required policy/security validation where relevant;
  4. Evidence recorded in CHECKLIST.md; and
  5. A Git commit hash.
- If a phase gate is incomplete, say exactly:
  “Phase [N] is not complete. Remaining gate items are: ...”
  Then recommend only the next smallest unblocked checklist task.
- If every gate criterion is verified, say exactly:
  “Phase [N] is complete and verified. Do not begin Phase [N+1] in this
  thread.”
- On verified phase completion, produce:
  1. Updated CHECKLIST.md content for the finished phase, gate, and dashboard.
  2. Updated HANDOFF.md content that sets Phase [N+1] and its first task.
  3. A phase-completion record with evidence, tests, limitations, simulations,
     unresolved risks, dependencies, commit hash, and proposed Git tag.
  4. Exact Git commands to save, commit, tag, and push phase completion.
  5. A filled-in continuation prompt for the first task of Phase [N+1].
  6. A direct instruction to create a new Perplexity thread only after I have
     saved the Markdown files and confirmed commit/tag results.
- Do not tell me to switch threads until I confirm the completion commit and
  tag exist.

## Required output at end of each task

Provide:
1. Exact files to create or modify.
2. Complete code blocks only for files that must change.
3. Kali Linux commands to run.
4. Validation steps and expected results.
5. A factual CHECKLIST.md update block.
6. A factual HANDOFF.md update block.
7. Safe Git staging/commit/push commands and a recommended commit message.
8. The next smallest recommended checklist task.
9. Current phase-gate status: complete, incomplete, or blocked.

Wait for my actual terminal, test, and Git output before saying that any task,
test, or phase is completed.