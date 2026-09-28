# TODO(phase-9): Policy-as-Code guardrails for Zone 3 MCP middleware.
# Encodes the least-privilege split described in the blueprint:
#   - principal "agent"        -> read-only (listAttackPaths, planRemediation)
#   - principal "soc-operator" -> write/execute (writeRemediationPlan, isolate)
package soc.guardrails

default allow = false

# allow[msg] { ... }  # TODO: implement rules per Agent B deep-dive section
