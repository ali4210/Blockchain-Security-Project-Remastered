# TODO(phase-10b): Policy-as-Code guardrails for Zone 5 forensics. [NEW V10.1]
# See blueprint Section 4.9.
#   principal "agent"        -> read-only (list_evidence, read_derived,
#                                plan_acquisition, draft_report)
#   principal "soc-operator" -> acquire, seal, release_report, legal_hold
#   nobody                   -> modify_original, delete_original (always denied)
package soc.forensics

default allow := false

agent_actions := {
  "forensics.list_evidence", "forensics.read_derived",
  "forensics.plan_acquisition", "forensics.draft_report"
}

operator_actions := {
  "forensics.acquire", "forensics.seal",
  "forensics.release_report", "forensics.legal_hold"
}

# TODO: implement allow rules per blueprint Section 4.9
# allow if { input.principal.role == "agent"; input.action in agent_actions }
# allow if { input.principal.role == "soc-operator"; input.principal.authenticated == true; input.action in operator_actions }
