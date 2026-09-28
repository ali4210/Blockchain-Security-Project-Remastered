"""
TODO(phase-9): Open Policy Agent (OPA) evaluator.
Every agent tool call must be evaluated against config/opa/agent_policy.rego
before execution — least privilege for "agent" principal, HITL gate for
"soc-operator" principal (see Agent B deep-dive in the blueprint).
"""


def evaluate(_principal: str, _action: str) -> bool:
    raise NotImplementedError("not implemented — see checklist Phase 9")
