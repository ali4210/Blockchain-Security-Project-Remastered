"""
Task P11-010: Agent Consensus Integration Client.
Provides rate-limited, schema-validated, and OPA-guarded client dispatchers
for Agents B, E, and G to safely consume Zone 6 consensus monitoring tools.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
import time
from typing import Any, Dict, List, Optional, Set

from src.consensus.consensus_mcp import ConsensusMcpRegistry
from src.consensus.consensus_policy import ConsensusPolicyEvaluator


class RateLimitExceededError(Exception):
    """Raised when an agent exceeds its assigned consensus query rate limit."""
    pass


@dataclass
class TokenBucket:
    capacity: float
    tokens: float
    refill_rate_per_sec: float
    last_refill: float

    def consume(self, cost: float = 1.0) -> bool:
        now = time.time()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate_per_sec)
        self.last_refill = now

        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False


class AgentConsensusClient:
    """Client interface for AI agents interacting with Zone 6 consensus tools."""

    ALLOWED_AGENTS: Set[str] = {"agent_b", "agent_e", "agent_g"}

    def __init__(
        self,
        agent_id: str,
        mcp_registry: Optional[ConsensusMcpRegistry] = None,
        policy_evaluator: Optional[ConsensusPolicyEvaluator] = None,
        rate_limit_capacity: float = 10.0,
        rate_limit_refill_per_sec: float = 2.0,
    ):
        clean_id = agent_id.lower().strip()
        if clean_id not in self.ALLOWED_AGENTS:
            raise ValueError(f"Unauthorized or unconfigured agent identifier '{agent_id}'")

        self.agent_id = clean_id
        self.mcp_registry = mcp_registry or ConsensusMcpRegistry()
        self.policy_evaluator = policy_evaluator or ConsensusPolicyEvaluator()

        self._rate_limiter = TokenBucket(
            capacity=rate_limit_capacity,
            tokens=rate_limit_capacity,
            refill_rate_per_sec=rate_limit_refill_per_sec,
            last_refill=time.time(),
        )

    def execute_tool(self, tool_name: str, arguments: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Executes a consensus monitoring tool on behalf of the agent,
        enforcing OPA role boundaries and token-bucket rate limits.
        """
        # 1. Evaluate OPA policy boundary
        policy_result = self.policy_evaluator.evaluate(
            principal=self.agent_id,
            action=tool_name,
            resource="consensus_mcp",
            token_valid=False,
        )

        if not policy_result.allowed:
            raise PermissionError(
                f"Agent '{self.agent_id}' is denied execution of tool '{tool_name}': {policy_result.reason}"
            )

        # 2. Enforce Token Bucket Rate Limiting
        if not self._rate_limiter.consume(1.0):
            raise RateLimitExceededError(
                f"Agent '{self.agent_id}' exceeded consensus query rate limit. "
                "Cooling down to prevent node saturation."
            )

        # 3. Dispatch tool execution via MCP registry
        result = self.mcp_registry.call_tool(tool_name, arguments or {})
        return result

    # Agent B convenience helper: correlate contract events with mempool and reorgs
    def query_pipeline_telemetry(self, limit: int = 25) -> Dict[str, Any]:
        return self.execute_tool("get_mempool_telemetry", {"limit": limit})

    def query_reorg_history(self, min_severity: str = "ALL") -> Dict[str, Any]:
        return self.execute_tool("get_reorg_history", {"min_severity": min_severity})

    # Agent E convenience helper: verify network topology and centralization risks
    def query_network_stability(self) -> Dict[str, Any]:
        topology = self.execute_tool("get_topology_summary")
        concentration = self.execute_tool("get_concentration_metrics")
        return {
            "status": "success",
            "data": {
                "topology": topology.get("data", {}),
                "concentration": concentration.get("data", {}),
            },
        }

    # Agent G convenience helper: incident response consensus correlation
    def query_incident_consensus_context(self, suspected_miner: Optional[str] = None) -> Dict[str, Any]:
        reorgs = self.execute_tool("get_reorg_history")
        eclipse = self.execute_tool("evaluate_eclipse_status")
        selfish = None
        if suspected_miner:
            selfish = self.execute_tool("evaluate_selfish_mining", {"miner_or_pool": suspected_miner})

        return {
            "status": "success",
            "data": {
                "reorgs": reorgs.get("data", {}),
                "eclipse": eclipse.get("data", {}),
                "selfish_mining": selfish.get("data", {}) if selfish else None,
            },
        }
