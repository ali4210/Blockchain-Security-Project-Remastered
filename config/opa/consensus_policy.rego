# TODO(phase-11): Policy-as-Code guardrails for Zone 6 consensus monitoring. [NEW V10.2]
# See blueprint Section 4A.7.
package soc.consensus

default allow := false

agent_actions := {
  "consensus.read_report", "consensus.correlate_finding"
}

operator_actions := {
  "consensus.trigger_mitigation", "consensus.override_threshold"
}

# TODO: implement allow rules per blueprint Section 4A.7
# allow if { input.principal.role == "agent"; input.action in agent_actions }
# allow if { input.principal.role == "soc-operator"; input.principal.authenticated == true; input.action in operator_actions }
