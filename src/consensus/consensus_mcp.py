"""
Task P11-006: Consensus Monitor MCP Functions Registration.
Exposes read-only MCP analytical inspection tools for P2P network telemetry,
chain reorganizations, stake/hashpower concentration, selfish mining, and eclipse status.
"""

from typing import Any, Callable, Dict, List, Optional

from src.consensus.concentration_tracker import ConsensusConcentrationTracker
from src.consensus.eclipse_detector import P2PEclipseDetector
from src.consensus.p2p_listener import ConsensusNetworkListener
from src.consensus.reorg_monitor import ChainReorgMonitor
from src.consensus.selfish_mining_detector import SelfishMiningDetector


class ConsensusMcpRegistry:
    """Manages and dispatches consensus-layer read-only MCP monitoring tools."""

    def __init__(
        self,
        p2p_listener: Optional[ConsensusNetworkListener] = None,
        reorg_monitor: Optional[ChainReorgMonitor] = None,
        concentration_tracker: Optional[ConsensusConcentrationTracker] = None,
        selfish_detector: Optional[SelfishMiningDetector] = None,
        eclipse_detector: Optional[P2PEclipseDetector] = None,
    ):
        self.p2p_listener = p2p_listener or ConsensusNetworkListener()
        self.reorg_monitor = reorg_monitor or ChainReorgMonitor()
        self.concentration_tracker = concentration_tracker or ConsensusConcentrationTracker()
        self.selfish_detector = selfish_detector or SelfishMiningDetector()
        self.eclipse_detector = eclipse_detector or P2PEclipseDetector()

        self._tools: Dict[str, Dict[str, Any]] = {}
        self._handlers: Dict[str, Callable[..., Dict[str, Any]]] = {}
        self._register_default_tools()

    def _register_default_tools(self) -> None:
        # Tool 1: get_mempool_telemetry
        self.register_tool(
            name="get_mempool_telemetry",
            description="Retrieves pending transactions in mempool with propagation delay statistics.",
            input_schema={
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "description": "Max transactions to return (1-100)"}
                },
            },
            handler=self._handle_get_mempool_telemetry,
        )

        # Tool 2: get_topology_summary
        self.register_tool(
            name="get_topology_summary",
            description="Queries P2P peer table topological diversity, ASN distribution, and subnet clustering.",
            input_schema={"type": "object", "properties": {}},
            handler=self._handle_get_topology_summary,
        )

        # Tool 3: get_reorg_history
        self.register_tool(
            name="get_reorg_history",
            description="Retrieves recorded chain reorganization events, depths, common ancestors, and severity levels.",
            input_schema={
                "type": "object",
                "properties": {
                    "min_severity": {
                        "type": "string",
                        "enum": ["ALL", "MICRO_FORK", "SHALLOW_REORG", "DEEP_REORG_ANOMALY", "CRITICAL_FINALITY_VIOLATION"],
                    }
                },
            },
            handler=self._handle_get_reorg_history,
        )

        # Tool 4: get_concentration_metrics
        self.register_tool(
            name="get_concentration_metrics",
            description="Evaluates validator stake or miner hashpower concentration, Nakamoto coefficient, and HHI.",
            input_schema={"type": "object", "properties": {}},
            handler=self._handle_get_concentration_metrics,
        )

        # Tool 5: evaluate_selfish_mining
        self.register_tool(
            name="evaluate_selfish_mining",
            description="Evaluates statistical orphan rate z-scores and private lead dump streaks for a target miner.",
            input_schema={
                "type": "object",
                "properties": {
                    "miner_or_pool": {"type": "string", "description": "Miner or pool identifier to evaluate"}
                },
                "required": ["miner_or_pool"],
            },
            handler=self._handle_evaluate_selfish_mining,
        )

        # Tool 6: evaluate_eclipse_status
        self.register_tool(
            name="evaluate_eclipse_status",
            description="Evaluates current peer table connections for adversarial ASN or subnet monopolization.",
            input_schema={"type": "object", "properties": {}},
            handler=self._handle_evaluate_eclipse_status,
        )

    def register_tool(
        self,
        name: str,
        description: str,
        input_schema: Dict[str, Any],
        handler: Callable[..., Dict[str, Any]],
    ) -> None:
        self._tools[name] = {
            "name": name,
            "description": description,
            "inputSchema": input_schema,
            "category": "READ",
            "zone": "ZONE_6_CONSENSUS",
        }
        self._handlers[name] = handler

    def list_tools(self) -> List[Dict[str, Any]]:
        return list(self._tools.values())

    def call_tool(self, name: str, arguments: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if name not in self._handlers:
            return {"status": "error", "error": f"Unknown consensus tool: '{name}'"}

        args = arguments or {}
        try:
            result = self._handlers[name](**args)
            return {"status": "success", "data": result}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    # Handler implementations
    def _handle_get_mempool_telemetry(self, limit: int = 50) -> Dict[str, Any]:
        limit = max(1, min(100, int(limit)))
        all_txs = self.p2p_listener.get_all_mempool_transactions()
        total_txs = len(all_txs)
        selected = all_txs[:limit]
        delays = [tx.propagation_delay_ms for tx in all_txs]
        avg_delay = round(sum(delays) / len(delays), 2) if delays else 0.0

        return {
            "total_pending": total_txs,
            "average_propagation_delay_ms": avg_delay,
            "returned_count": len(selected),
            "transactions": [
                {
                    "tx_hash": tx.tx_hash,
                    "from": tx.from_address,
                    "to": tx.to_address,
                    "gas_price": tx.gas_price,
                    "propagation_delay_ms": tx.propagation_delay_ms,
                }
                for tx in selected
            ],
        }

    def _handle_get_topology_summary(self) -> Dict[str, Any]:
        return self.p2p_listener.get_topology_summary()

    def _handle_get_reorg_history(self, min_severity: str = "ALL") -> Dict[str, Any]:
        events = self.reorg_monitor.get_reorg_history()
        if min_severity != "ALL":
            events = [e for e in events if e.severity.value == min_severity]
        return {
            "canonical_tip_number": self.reorg_monitor.canonical_tip_number,
            "canonical_tip_hash": self.reorg_monitor.canonical_tip_hash,
            "total_reorg_events": len(events),
            "events": [e.to_dict() for e in events],
        }

    def _handle_get_concentration_metrics(self) -> Dict[str, Any]:
        metrics = self.concentration_tracker.calculate_metrics()
        return metrics.to_dict()

    def _handle_evaluate_selfish_mining(self, miner_or_pool: str) -> Dict[str, Any]:
        alert = self.selfish_detector.evaluate_miner(miner_or_pool)
        if alert is None:
            return {
                "miner_or_pool": miner_or_pool,
                "threat_level": "CLEAR",
                "message": "No statistical selfish mining anomaly detected.",
            }
        return alert.to_dict()

    def _handle_evaluate_eclipse_status(self) -> Dict[str, Any]:
        peers = list(self.p2p_listener._peers.values())
        alert = self.eclipse_detector.evaluate_peers(peers)
        if alert is None:
            return {
                "threat_level": "CLEAR",
                "total_peers": len(peers),
                "message": "Peer table topological diversity satisfies safety thresholds.",
            }
        return alert.to_dict()
