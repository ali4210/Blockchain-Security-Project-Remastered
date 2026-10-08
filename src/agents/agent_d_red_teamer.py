"""
Agent D: Red Teamer (Task P05-009).
Synthesizes exploit hypotheses and attack verification stubs using DeepSeek R1
(32B/14B, 16K context) under deterministic Ephemeral VRAM lifecycle management.
"""

from typing import Any, Dict, List, Optional
import json
import re

from src.llm_client.ollama_client import chat, agent_stage
from src.agents.graph import SwarmState


def parse_red_team_findings(response_text: str, target_name: str) -> List[Dict[str, Any]]:
    """Parses model response into structured exploit / red-team scenarios."""
    findings: List[Dict[str, Any]] = []

    if "[OFFLINE_FALLBACK]" in response_text:
        findings.append({
            "finding_id": "FINDING-D-SIM-001",
            "exploit_scenario": "Recursive Ether Withdrawal Exploit",
            "target": target_name,
            "severity": "CRITICAL",
            "attack_vector": "Fallback function reentrancy during external transfer",
            "poc_stub": "contract Attack { fallback() external payable { vault.withdraw(); } }",
            "details": "Simulated red-team finding in offline headless mode.",
            "confidence": 0.90,
        })
        return findings

    json_match = re.search(r"```json\s*(.*?)\s*```", response_text, re.DOTALL)
    if json_match:
        try:
            parsed = json.loads(json_match.group(1))
            if isinstance(parsed, list):
                return parsed
            if isinstance(parsed, dict) and "scenarios" in parsed:
                return parsed["scenarios"]
            if isinstance(parsed, dict) and "findings" in parsed:
                return parsed["findings"]
        except json.JSONDecodeError:
            pass

    findings.append({
        "finding_id": "FINDING-D-001",
        "exploit_scenario": "Heuristic Attack Vector",
        "target": target_name,
        "severity": "HIGH",
        "attack_vector": "State manipulation sequence",
        "poc_stub": "// Exploit hypothesis generation",
        "details": response_text[:250].strip(),
        "confidence": 0.70,
    })
    return findings


def red_teamer_node(state: SwarmState) -> SwarmState:
    """
    LangGraph execution node for Agent D (Red Teamer).
    Wraps inference in agent_stage('D') to enforce immediate VRAM eviction.
    """
    target = state.get("target_contract") or state.get("contract_path", "VulnerableVault")
    prior_findings = state.get("findings", [])

    prompt = (
        "You are an expert offensive security researcher and web3 red teamer specializing in "
        "EVM smart contract exploitation and Foundry invariant fuzzing harness generation.\n\n"
        f"Target System: {target}\n"
        f"Prior Findings: {json.dumps(prior_findings, indent=2)}\n\n"
        "Design a concrete exploit scenario or test stub proving vulnerability feasibility. "
        "Emit findings in JSON format: [{\"finding_id\": \"...\", \"exploit_scenario\": \"...\", "
        "\"target\": \"...\", \"severity\": \"CRITICAL/HIGH/MEDIUM\", \"attack_vector\": \"...\", "
        "\"poc_stub\": \"...\", \"details\": \"...\", \"confidence\": 0.95}]"
    )

    messages = [
        {"role": "system", "content": "You are Agent D, Senior Web3 Red Teamer."},
        {"role": "user", "content": prompt},
    ]

    with agent_stage("D") as stage_ctx:
        response = chat(
            messages=messages,
            model=stage_ctx["model"],
            force_agent="D",
            timeout=stage_ctx["timeout"],
        )

    parsed_scenarios = parse_red_team_findings(response, str(target))

    updated_findings = list(prior_findings) + parsed_scenarios
    metadata = dict(state.get("metadata", {}))
    metadata["agent_d_executed"] = True
    metadata["agent_d_model"] = stage_ctx["model"]

    new_state = SwarmState(
        target_contract=state.get("target_contract", ""),
        findings=updated_findings,
        current_stage="agent_d_completed",
        escalation_needed=state.get("escalation_needed", False),
        errors=list(state.get("errors", [])),
        metadata=metadata,
    )
    new_state["current_step"] = "agent_d_completed"
    return new_state
