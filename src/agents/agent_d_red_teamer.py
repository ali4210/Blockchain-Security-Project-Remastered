"""
Agent D: Red Teamer (Task P05-009, P12-010).
Synthesizes exploit hypotheses and attack verification stubs using DeepSeek R1
(32B/14B, 16K context) under deterministic Ephemeral VRAM lifecycle management.
Synthesizes authorized PoC exploit stubs for Zone 7 wallet replay and hijacking flaws.
"""

from typing import Any, Dict, List, Optional
import json
import re

from src.llm_client.ollama_client import chat, agent_stage
from src.agents.state import SwarmState


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
        except json.JSONDecodeError:
            pass

    try:
        parsed = json.loads(response_text)
        if isinstance(parsed, list):
            return parsed
    except json.JSONDecodeError:
        pass

    findings.append({
        "finding_id": "FINDING-D-RAW-001",
        "exploit_scenario": "Exploit Synthesis Output",
        "target": target_name,
        "severity": "HIGH",
        "attack_vector": "Heuristic assessment based on auditor findings",
        "poc_stub": "// No explicit PoC code emitted",
        "details": response_text[:200] if response_text else "No details extracted.",
        "confidence": 0.50,
    })
    return findings


def run_agent_d(state: SwarmState) -> SwarmState:
    """
    LangGraph execution node for Agent D (Red Teamer).
    Wraps inference in agent_stage("D") to enforce immediate VRAM eviction.
    Synthesizes authorized, bounded PoC harness stubs for detected wallet flaws.
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

    # Zone 7 Wallet-Specific PoC Synthesis
    wallet_pocs: List[Dict[str, Any]] = []
    wallet_rules = {f.get("rule_id") for f in prior_findings if "rule_id" in f}

    if "RULE-WLT-001" in wallet_rules:
        wallet_pocs.append({
            "finding_id": "FINDING-D-WLT-001",
            "exploit_scenario": "Signature Replay Fund Drainage",
            "target": str(target),
            "severity": "CRITICAL",
            "attack_vector": "Resubmission of valid signature tuple (v,r,s) without nonce invalidation",
            "poc_stub": (
                "function testSignatureReplay() external {\n"
                "    wallet.executeTransfer(attacker, 1 ether, v, r, s);\n"
                "    wallet.executeTransfer(attacker, 1 ether, v, r, s); // Replay succeeds\n"
                "}"
            ),
            "details": "Authorized PoC proving absence of monotonic nonce gating.",
            "confidence": 0.99,
        })

    if "RULE-WLT-003" in wallet_rules:
        wallet_pocs.append({
            "finding_id": "FINDING-D-WLT-003",
            "exploit_scenario": "Arbitrary Delegatecall Owner Takeover",
            "target": str(target),
            "severity": "CRITICAL",
            "attack_vector": "Arbitrary delegatecall target execution overwriting storage slot 0",
            "poc_stub": (
                "function testDelegatecallTakeover() external {\n"
                "    wallet.executeDelegatecall(address(maliciousLogic), abi.encodeWithSignature('overwriteOwner()'));\n"
                "}"
            ),
            "details": "Authorized PoC verifying full ownership takeover via unchecked delegatecall.",
            "confidence": 0.99,
        })

    updated_findings = list(prior_findings) + parsed_scenarios + wallet_pocs
    metadata = dict(state.get("metadata", {}))
    metadata["agent_d_executed"] = True
    metadata["agent_d_model"] = stage_ctx["model"]
    if wallet_pocs:
        metadata["wallet_poc_synthesized"] = True

    new_state = SwarmState(
        target_contract=state.get("target_contract", ""),
        findings=updated_findings,
        current_stage="agent_d_completed",
        escalation_needed=state.get("escalation_needed", False) or bool(wallet_pocs),
        errors=list(state.get("errors", [])),
        metadata=metadata,
    )
    new_state["current_step"] = "agent_d_completed"
    return new_state

# Backward compatibility alias for LangGraph pipeline
red_teamer_node = run_agent_d
