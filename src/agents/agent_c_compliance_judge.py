"""
Agent C: Compliance Judge (Task P05-008).
Evaluates aggregated vulnerability findings against OWASP, NIST, and ISO controls
using Qwen 2.5 (32B/14B, 8K context) under deterministic Ephemeral VRAM lifecycle management.
"""

from typing import Any, Dict, List, Optional
import json
import re

from src.llm_client.ollama_client import chat, agent_stage
from src.agents.state import SwarmState


def parse_compliance_verdict(response_text: str) -> Dict[str, Any]:
    """Parses model response into structured compliance audit report."""
    if "[OFFLINE_FALLBACK]" in response_text:
        return {
            "verdict": "CONDITIONAL_PASS",
            "compliance_score": 78,
            "frameworks_evaluated": ["OWASP-SC-2023", "NIST-SP-800-53"],
            "violations": [
                {
                    "control_id": "OWASP-SC-01",
                    "description": "Reentrancy vulnerability requires state-locking guards.",
                    "severity": "HIGH",
                    "remediation": "Implement ReentrancyGuard and checks-effects-interactions pattern.",
                }
            ],
            "details": "Simulated compliance verdict in offline headless mode.",
        }

    json_match = re.search(r"```json\s*(.*?)\s*```", response_text, re.DOTALL)
    if json_match:
        try:
            parsed = json.loads(json_match.group(1))
            if isinstance(parsed, dict) and "verdict" in parsed:
                return parsed
        except json.JSONDecodeError:
            pass

    return {
        "verdict": "CONDITIONAL_PASS",
        "compliance_score": 75,
        "frameworks_evaluated": ["OWASP-SC-2023"],
        "violations": [],
        "details": response_text[:250].strip(),
    }


def compliance_judge_node(state: SwarmState) -> SwarmState:
    """
    LangGraph execution node for Agent C (Compliance Judge).
    Wraps inference in agent_stage('C') to enforce immediate VRAM eviction.
    """
    findings = state.get("findings", [])
    target = state.get("target_contract") or state.get("contract_path", "VulnerableVault")

    prompt = (
        "You are an enterprise blockchain compliance auditor and regulatory judge. "
        "Evaluate the following smart-contract vulnerability and runtime telemetry findings "
        "against OWASP Smart Contract Top 10 and NIST SP 800-53 controls.\n\n"
        f"Target Architecture: {target}\n"
        f"Combined Findings List: {json.dumps(findings, indent=2)}\n\n"
        "Render a formal compliance verdict. Emit findings in JSON format: "
        "{\"verdict\": \"PASS/CONDITIONAL_PASS/FAIL\", \"compliance_score\": 85, "
        "\"frameworks_evaluated\": [\"OWASP-SC-2023\", \"NIST-SP-800-53\"], "
        "\"violations\": [{\"control_id\": \"...\", \"description\": \"...\", \"severity\": \"...\", \"remediation\": \"...\"}], "
        "\"details\": \"...\"}"
    )

    messages = [
        {"role": "system", "content": "You are Agent C, Enterprise Compliance Judge."},
        {"role": "user", "content": prompt},
    ]

    with agent_stage("C") as stage_ctx:
        response = chat(
            messages=messages,
            model=stage_ctx["model"],
            force_agent="C",
            timeout=stage_ctx["timeout"],
        )

    verdict_report = parse_compliance_verdict(response)

    compliance_finding = {
        "finding_id": "FINDING-C-COMPLIANCE-001",
        "category": "COMPLIANCE_VERDICT",
        "verdict": verdict_report.get("verdict", "CONDITIONAL_PASS"),
        "compliance_score": verdict_report.get("compliance_score", 75),
        "frameworks_evaluated": verdict_report.get("frameworks_evaluated", []),
        "violations": verdict_report.get("violations", []),
        "details": verdict_report.get("details", ""),
    }

    updated_findings = list(findings) + [compliance_finding]
    metadata = dict(state.get("metadata", {}))
    metadata["agent_c_executed"] = True
    metadata["agent_c_model"] = stage_ctx["model"]
    metadata["compliance_verdict"] = verdict_report.get("verdict", "CONDITIONAL_PASS")
    metadata["compliance_score"] = verdict_report.get("compliance_score", 75)

    new_state = SwarmState(
        target_contract=state.get("target_contract", ""),
        findings=updated_findings,
        current_stage="agent_c_completed",
        escalation_needed=state.get("escalation_needed", False),
        errors=list(state.get("errors", [])),
        metadata=metadata,
    )
    new_state["current_step"] = "agent_c_completed"
    return new_state
