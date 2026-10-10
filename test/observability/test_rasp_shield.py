"""
Task P08-003: Unit Tests for RASP Shield Engine.
Validates read-only RPC trace analysis, GraphSense cluster risk ingestion,
Forta/Rekt threat signal integration, composite risk scoring, and RaspFinding emission.
"""

import unittest
from unittest.mock import MagicMock

from src.observability.rasp_shield import (
    RaspShield,
    RaspFinding,
    ThreatSignal,
    ThreatSignalSource,
    ThreatSeverity,
)


class TestRaspShield(unittest.TestCase):
    def setUp(self):
        self.mock_rpc_fn = MagicMock()
        self.mock_graphsense_fn = MagicMock()
        self.shield = RaspShield(
            rpc_query_fn=self.mock_rpc_fn,
            graphsense_query_fn=self.mock_graphsense_fn,
        )

    def test_benign_transaction_evaluation(self):
        # Benign simulation and valid receipt
        def rpc_dispatcher(method, params=None):
            if method == "eth_call":
                return {"status": "success", "result": "0x"}
            elif method == "eth_getTransactionReceipt":
                return {"status": "0x1", "gasUsed": 21000}
            return {}

        self.mock_rpc_fn.side_effect = rpc_dispatcher
        self.mock_graphsense_fn.return_value = {
            "entity": "Coinbase",
            "is_sanctioned": False,
            "risk_category": "exchange",
        }

        finding = self.shield.evaluate_transaction(
            target_contract="0x1111111111111111111111111111111111111111",
            tx_hash="0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            from_address="0x2222222222222222222222222222222222222222",
            call_depth=1,
        )

        self.assertIsInstance(finding, RaspFinding)
        self.assertFalse(finding.is_suspicious)
        self.assertEqual(finding.risk_score, 0.0)
        self.assertEqual(len(finding.signals), 0)
        self.assertEqual(finding.cluster_entity, "Coinbase")

    def test_abnormal_call_depth_and_reverted_sim_triggers_suspicion(self):
        def rpc_dispatcher(method, params=None):
            if method == "eth_call":
                return {"status": "reverted", "error": "Execution reverted"}
            elif method == "eth_getTransactionReceipt":
                return {"status": "0x1"}
            return {}

        self.mock_rpc_fn.side_effect = rpc_dispatcher
        self.mock_graphsense_fn.return_value = {
            "entity": None,
            "is_sanctioned": False,
            "risk_category": "unknown",
        }

        finding = self.shield.evaluate_transaction(
            target_contract="0x1111111111111111111111111111111111111111",
            tx_hash="0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            from_address="0x3333333333333333333333333333333333333333",
            call_depth=6,  # Exceeds threshold of 4
        )

        self.assertTrue(finding.is_suspicious)
        self.assertGreater(finding.risk_score, 0.5)
        self.assertEqual(finding.severity, ThreatSeverity.HIGH)
        indicators = [s.indicator for s in finding.signals]
        self.assertIn("ABNORMAL_CALL_DEPTH", indicators)
        self.assertIn("TRACE_SIMULATION_REVERT", indicators)

    def test_sanctioned_graphsense_cluster_flags_critical(self):
        def rpc_dispatcher(method, params=None):
            if method == "eth_call":
                return {"status": "success"}
            elif method == "eth_getTransactionReceipt":
                return {"status": "0x1"}
            return {}

        self.mock_rpc_fn.side_effect = rpc_dispatcher
        self.mock_graphsense_fn.return_value = {
            "entity": "TornadoCash",
            "is_sanctioned": True,
            "risk_category": "mixer",
        }

        finding = self.shield.evaluate_transaction(
            target_contract="0x1111111111111111111111111111111111111111",
            tx_hash="0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            from_address="0x4444444444444444444444444444444444444444",
        )

        self.assertTrue(finding.is_suspicious)
        self.assertEqual(finding.severity, ThreatSeverity.CRITICAL)
        self.assertGreaterEqual(finding.risk_score, 0.99)
        self.assertEqual(finding.cluster_entity, "TornadoCash")

    def test_forta_and_rekt_external_signals_integration(self):
        def rpc_dispatcher(method, params=None):
            if method == "eth_call":
                return {"status": "success"}
            elif method == "eth_getTransactionReceipt":
                return {"status": "0x1"}
            return {}

        self.mock_rpc_fn.side_effect = rpc_dispatcher
        self.mock_graphsense_fn.return_value = {
            "entity": None,
            "is_sanctioned": False,
            "risk_category": "retail",
        }

        external = [
            ThreatSignal(
                source=ThreatSignalSource.FORTA,
                severity=ThreatSeverity.HIGH,
                indicator="FORTA_FLASHLOAN_ATTACK_AGENT",
                details={"bot_id": "0xabc", "alert_id": "FLASH-LOAN-01"},
            ),
            ThreatSignal(
                source=ThreatSignalSource.REKT,
                severity=ThreatSeverity.CRITICAL,
                indicator="REKT_KNOWN_EXPLOIT_PATTERN",
                details={"rekt_id": "REKT-2026-VAULT-04"},
            ),
        ]

        finding = self.shield.evaluate_transaction(
            target_contract="0x1111111111111111111111111111111111111111",
            tx_hash="0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            from_address="0x5555555555555555555555555555555555555555",
            external_signals=external,
        )

        self.assertTrue(finding.is_suspicious)
        self.assertEqual(finding.severity, ThreatSeverity.CRITICAL)
        self.assertEqual(len(finding.signals), 2)
        d = finding.to_dict()
        self.assertEqual(d["finding_id"], finding.finding_id)
        self.assertEqual(len(d["signals"]), 2)

    def test_default_clients_initialization(self):
        default_shield = RaspShield()
        self.assertIsNotNone(default_shield._rpc_fn)
        self.assertIsNotNone(default_shield._graphsense_fn)


if __name__ == "__main__":
    unittest.main()
