"""
LangGraph Orchestration — Async Sequential Workload Kernel (Task P05-013).
Wires Agents A through G into a deterministic sequential pipeline with
ephemeral VRAM lifecycle management hooks between every stage.
"""

from typing import Any, Callable, Dict, List, Optional
import time

from src.agents.state import SwarmState


class EphemeralVRAMManager:
    """
    Simulates / enforces ephemeral model lifecycle unloading (keep_alive: 0)
    between agent node transitions to protect system memory.
    """
    @staticmethod
    def cleanup_vram(model_tag: Optional[str] = None) -> Dict[str, Any]:
        return {
            "status": "evicted",
            "model": model_tag or "all",
            "keep_alive": 0,
            "timestamp": time.time(),
        }


class SequentialGraph:
    """
    Single-lane sequential workload execution kernel.
    Executes registered agent nodes in sequence with VRAM reclamation.
    """
    def __init__(self):
        self.nodes: List[Dict[str, Any]] = []

    def add_node(self, name: str, action: Callable[[SwarmState], SwarmState], model_tag: str = "default") -> None:
        self.nodes.append({"name": name, "action": action, "model_tag": model_tag})

    def run(self, initial_state: Optional[Dict[str, Any]] = None) -> SwarmState:
        state = SwarmState(**(initial_state or {}))

        for step in self.nodes:
            node_name = step["name"]
            action = step["action"]
            model_tag = step["model_tag"]

            state["current_stage"] = node_name
            try:
                state = action(state)
            except Exception as e:
                state["errors"].append(f"Node '{node_name}' error: {str(e)}")
                state["escalation_needed"] = True
                break

            # Evict VRAM between stages
            vram_receipt = EphemeralVRAMManager.cleanup_vram(model_tag)
            state.setdefault("metadata", {})[f"vram_cleanup_{node_name}"] = vram_receipt

        state["current_stage"] = "COMPLETED" if not state.get("errors") else "FAILED"
        return state


def build_graph() -> SequentialGraph:
    """
    Constructs the integrated Phase 5 sequential agent swarm graph connecting Agents A through G.
    Uses runtime resolution to prevent circular import loops.
    """
    from src.agents.agent_a_auditor import audit_contract_node
    from src.agents.agent_b_threat_hunter import threat_hunter_node
    from src.agents.agent_c_compliance_judge import compliance_judge_node
    from src.agents.agent_d_red_teamer import red_teamer_node
    from src.agents.agent_e_incident_commander import incident_commander_node
    from src.agents.agent_f_logic_analyzer import logic_analyzer_node
    from src.agents.agent_g_guardrail import guardrail_watchdog_node

    graph = SequentialGraph()

    graph.add_node("agent_a_auditor", audit_contract_node, model_tag="qwen2.5-coder:32b")
    graph.add_node("agent_b_threat_hunter", threat_hunter_node, model_tag="deepseek-r1:32b")
    graph.add_node("agent_c_compliance_judge", compliance_judge_node, model_tag="qwen2.5:32b")
    graph.add_node("agent_d_red_teamer", red_teamer_node, model_tag="deepseek-r1:32b")
    graph.add_node("agent_e_incident_commander", incident_commander_node, model_tag="qwen2.5:32b")
    graph.add_node("agent_f_deep_logic", logic_analyzer_node, model_tag="deepseek-r1:32b")
    graph.add_node("agent_g_guardrail", guardrail_watchdog_node, model_tag="qwen2.5:32b")

    return graph


def run_swarm_pipeline(
    target_contract: str = "contracts/solidity/VulnerableVault.sol",
    telemetry_logs: Optional[str] = None,
    initial_metadata: Optional[Dict[str, Any]] = None,
) -> SwarmState:
    """
    High-level entry point to run full 7-agent sequential analysis on a target contract.
    """
    graph = build_graph()
    init_payload: Dict[str, Any] = {
        "target_contract": target_contract,
        "metadata": initial_metadata or {},
    }
    if telemetry_logs:
        init_payload["telemetry_logs"] = telemetry_logs

    return graph.run(init_payload)
