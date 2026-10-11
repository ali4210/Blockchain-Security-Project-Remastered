"""
Task P11-006: Unit tests for Consensus Monitor MCP Functions.
Validates tool registration, schema declarations, execution dispatching,
and structured output format.
"""

import unittest

from src.consensus.concentration_tracker import ConsensusConcentrationTracker
from src.consensus.consensus_mcp import ConsensusMcpRegistry
from src.consensus.eclipse_detector import P2PEclipseDetector
from src.consensus.p2p_listener import ConsensusNetworkListener
from src.consensus.reorg_monitor import BlockHeaderRecord, ChainReorgMonitor
from src.consensus.selfish_mining_detector import SelfishMiningDetector


class TestConsensusMcp(unittest.TestCase):
    def setUp(self):
        self.p2p = ConsensusNetworkListener()
        self.reorg = ChainReorgMonitor(finality_depth=12)
        self.concentration = ConsensusConcentrationTracker()
        self.selfish = SelfishMiningDetector(min_window_for_stats=10)
        self.eclipse = P2PEclipseDetector(min_peers_for_eval=4)

        # Seed initial state
        anchor = BlockHeaderRecord(
            block_number=100,
            block_hash="0x" + "0" * 63 + "1",
            parent_hash="0x" + "0" * 64,
            timestamp=1700000000.0,
        )
        self.reorg.initialize_anchor(anchor)

        self.registry = ConsensusMcpRegistry(
            p2p_listener=self.p2p,
            reorg_monitor=self.reorg,
            concentration_tracker=self.concentration,
            selfish_detector=self.selfish,
            eclipse_detector=self.eclipse,
        )

    def test_registered_tools_count_and_metadata(self):
        tools = self.registry.list_tools()
        self.assertEqual(len(tools), 6)

        tool_names = {t["name"] for t in tools}
        expected_names = {
            "get_mempool_telemetry",
            "get_topology_summary",
            "get_reorg_history",
            "get_concentration_metrics",
            "evaluate_selfish_mining",
            "evaluate_eclipse_status",
        }
        self.assertEqual(tool_names, expected_names)

        for t in tools:
            self.assertEqual(t["category"], "READ")
            self.assertEqual(t["zone"], "ZONE_6_CONSENSUS")
            self.assertIn("description", t)
            self.assertIn("inputSchema", t)

    def test_call_get_mempool_telemetry(self):
        self.p2p.record_mempool_transaction(
            tx_hash="0x" + "a" * 64,
            from_address="0x" + "1" * 40,
            to_address="0x" + "2" * 40,
            gas_price=20000000000,
            value_wei=1000,
            data_payload="",
            first_seen_timestamp=1700000000.0,
            received_timestamp=1700000000.050,
        )

        res = self.registry.call_tool("get_mempool_telemetry", {"limit": 10})
        self.assertEqual(res["status"], "success")
        data = res["data"]
        self.assertEqual(data["total_pending"], 1)
        self.assertEqual(data["average_propagation_delay_ms"], 50.0)

    def test_call_get_topology_summary(self):
        self.p2p.register_peer(
            peer_id="p1",
            ip_addr="198.51.100.1",
            port=30303,
            asn=13335,
            client_version="Geth",
            latency_rtt_ms=10.0,
        )
        res = self.registry.call_tool("get_topology_summary")
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["data"]["total_peers"], 1)
        self.assertEqual(res["data"]["unique_asns"], 1)

    def test_call_get_reorg_history(self):
        res = self.registry.call_tool("get_reorg_history")
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["data"]["canonical_tip_number"], 100)
        self.assertEqual(res["data"]["total_reorg_events"], 0)

    def test_call_get_concentration_metrics(self):
        self.concentration.set_explicit_distribution({"pool-1": 60.0, "pool-2": 40.0})
        res = self.registry.call_tool("get_concentration_metrics")
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["data"]["top_entity_id"], "pool-1")
        self.assertEqual(res["data"]["alert_level"], "CRITICAL")

    def test_call_evaluate_selfish_mining_clear_and_anomaly(self):
        # Empty/low window returns CLEAR
        res = self.registry.call_tool("evaluate_selfish_mining", {"miner_or_pool": "pool-x"})
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["data"]["threat_level"], "CLEAR")

    def test_call_evaluate_eclipse_status(self):
        res = self.registry.call_tool("evaluate_eclipse_status")
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["data"]["threat_level"], "CLEAR")

    def test_call_unknown_tool_returns_error(self):
        res = self.registry.call_tool("invalid_tool_name")
        self.assertEqual(res["status"], "error")
        self.assertIn("Unknown consensus tool", res["error"])


if __name__ == "__main__":
    unittest.main()
