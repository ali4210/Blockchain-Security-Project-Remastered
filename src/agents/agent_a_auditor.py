"""
Agent A: Smart-Contract Auditor (Task P05-006).
Dispatches AST and source analysis prompts to Qwen 2.5 Coder (32B/14B, 32K context)
under deterministic Ephemeral VRAM lifecycle management.
"""

from typing import Any, Dict, List, Optional
from pathlib import Path
import json
import re

from src.llm_client.ollama_client import chat, agent_stage
from src.agents.state import SwarmState


def extract_contract_source(state: SwarmState) -> str:
    """Retrieves target contract source code from state or default repository fixtures."""
    contract_path_str = state.get("target_contract") or state.get("contract_path")
    if contract_path_str:
        p = Path(contract_path_str)
        if p.is_file():
            return p.read_text(encoding="utf-8")

    default_fixture = Path("contracts/solidity/VulnerableVault.sol")
    if default_fixture.is_file():
        return default_fixture.read_text(encoding="utf-8")

    return "// Target contract source code unavailable"


def parse_auditor_findings(response_text: str, contract_name: str) -> List[Dict[str, Any]]:
    """Parses model response into structured security findings list."""
    findings: List[Dict[str, Any]] = []

    if "[OFFLINE_FALLBACK]" in response_text:
        findings.append({
            "finding_id": "FINDING-A-SIM-001",
            "vulnerability": "Reentrancy / State Mutability Check",
            "severity": "HIGH",
            "contract": contract_name,
            "details": "Simulated auditor finding in offline headless mode.",
            "confidence": 0.85,
        })
        return findings

    json_match = re.search(r"```json\s*(.*?)\s*```", response_text, re.DOTALL)
    if json_match:
        try:
            parsed = json.loads(json_match.group(1))
            if isinstance(parsed, list):
                return parsed
            if isinstance(parsed, dict) and "findings" in parsed:
                return parsed["findings"]
        except json.JSONDecodeError:
            pass

    findings.append({
        "finding_id": "FINDING-A-001",
        "vulnerability": "Security Analysis Summary",
        "severity": "MEDIUM",
        "contract": contract_name,
        "details": response_text[:250].strip(),
        "confidence": 0.70,
    })
    return findings


def audit_contract_node(state: SwarmState) -> SwarmState:
    """
    LangGraph execution node for Agent A (Smart-Contract Auditor).
    Wraps inference in agent_stage("A") to enforce immediate VRAM eviction.
    """
    contract_source = extract_contract_source(state)
    target_contract = state.get("target_contract") or state.get("contract_path", "contracts/solidity/VulnerableVault.sol")

    prompt = (
        "You are an expert smart-contract security auditor specializing in EVM and Move bytecode. "
        "Analyze the following contract source code for reentrancy, access control bypasses, "
        "and untrusted external calls.\n\n"
        f"Source:\n```solidity\n{contract_source}\n```\n\n"
        "Emit findings in JSON format: [{\"finding_id\": \"...\", \"vulnerability\": \"...\", "
        "\"severity\": \"HIGH/MEDIUM/LOW\", \"contract\": \"...\", \"details\": \"...\", \"confidence\": 0.9}]"
    )

    messages = [
        {"role": "system", "content": "You are Agent A, Lead Smart Contract Auditor."},
        {"role": "user", "content": prompt},
    ]

    with agent_stage("A") as stage_ctx:
        response = chat(
            messages=messages,
            model=stage_ctx["model"],
            force_agent="A",
            timeout=stage_ctx["timeout"],
        )

    parsed_findings = parse_auditor_findings(response, target_contract)

    updated_findings = list(state.get("findings", [])) + parsed_findings
    metadata = dict(state.get("metadata", {}))
    metadata["agent_a_executed"] = True
    metadata["agent_a_model"] = stage_ctx["model"]

    new_state = SwarmState(
        target_contract=target_contract,
        findings=updated_findings,
        current_stage="agent_a_completed",
        escalation_needed=state.get("escalation_needed", False),
        errors=list(state.get("errors", [])),
        metadata=metadata,
    )
    new_state["current_step"] = "agent_a_completed"
    return new_state
