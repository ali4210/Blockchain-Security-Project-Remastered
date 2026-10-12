"""
Task P13-002: Unit tests for AML Pattern Rules and Graph-Model Detector.
Validates:
1. Structuring (smurfing) heuristic detection within temporal windows.
2. Direct mixer / privacy pool interaction alerts.
3. Rapid layering hops across multi-hop peeling chains.
4. Clean telemetry batches yield zero false positives.
"""

import time
import unittest

from src.compliance.aml_detector import (
    AMLDetector,
    AMLRiskType,
    AMLTransaction,
)


class TestAMLDetector(unittest.TestCase):
    def setUp(self):
        self.detector = AMLDetector(
            structuring_threshold_wei=10**19,  # 10 ETH
            structuring_lower_bound_wei=8 * 10**18,  # 8 ETH
            max_layering_hop_interval_sec=120.0,
        )

    def test_structuring_detected_when_threshold_approached_repeatedly(self):
        now = time.time()
        sender = "0xSmurfingActor00000000000000000000000001"
        txs = [
            AMLTransaction(
                tx_hash="0x1111",
                sender=sender,
                recipient="0xRecipientA",
                value_wei=9 * 10**18,  # 9 ETH (just below 10 ETH)
                timestamp=now,
                block_number=1000,
            ),
            AMLTransaction(
                tx_hash="0x2222",
                sender=sender,
                recipient="0xRecipientB",
                value_wei=95 * 10**17,  # 9.5 ETH (just below 10 ETH)
                timestamp=now + 600,
                block_number=1050,
            ),
        ]

        findings = self.detector.evaluate_structuring(txs)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].risk_type, AMLRiskType.STRUCTURING)
        self.assertEqual(findings[0].severity, "HIGH")
        self.assertEqual(findings[0].rule_id, "RULE-AML-001")
        self.assertIn("0x1111", findings[0].evidence_tx_hashes)
        self.assertIn("0x2222", findings[0].evidence_tx_hashes)

    def test_mixer_interaction_detected(self):
        tx = AMLTransaction(
            tx_hash="0x3333",
            sender="0xRegularTrader",
            recipient="0xd90e2f925DA726b50C4Ed8D0Fb90Ad053324F31b",  # Tornado Router
            value_wei=10**18,
            timestamp=time.time(),
            block_number=2000,
        )

        findings = self.detector.evaluate_mixer_signals([tx])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].risk_type, AMLRiskType.MIXER_INTERACTION)
        self.assertEqual(findings[0].severity, "CRITICAL")
        self.assertEqual(findings[0].rule_id, "RULE-AML-002")

    def test_rapid_layering_detected_across_hops(self):
        now = time.time()
        # A -> B -> C -> D rapid sequence
        txs = [
            AMLTransaction(
                tx_hash="0xHop1",
                sender="0xOriginA",
                recipient="0xIntermediaryB",
                value_wei=10**19,
                timestamp=now,
                block_number=3000,
            ),
            AMLTransaction(
                tx_hash="0xHop2",
                sender="0xIntermediaryB",
                recipient="0xIntermediaryC",
                value_wei=98 * 10**17,  # minor fee deduction
                timestamp=now + 30,  # 30 seconds later
                block_number=3002,
            ),
            AMLTransaction(
                tx_hash="0xHop3",
                sender="0xIntermediaryC",
                recipient="0xDestinationD",
                value_wei=96 * 10**17,
                timestamp=now + 75,  # 45 seconds later
                block_number=3005,
            ),
        ]

        findings = self.detector.evaluate_layering_hops(txs)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].risk_type, AMLRiskType.RAPID_LAYERING)
        self.assertEqual(findings[0].severity, "HIGH")
        self.assertEqual(len(findings[0].evidence_tx_hashes), 3)

    def test_clean_transactions_yield_zero_findings(self):
        now = time.time()
        txs = [
            AMLTransaction(
                tx_hash="0xClean1",
                sender="0xUserA",
                recipient="0xUserB",
                value_wei=10**17,  # 0.1 ETH
                timestamp=now,
                block_number=4000,
            ),
            AMLTransaction(
                tx_hash="0xClean2",
                sender="0xUserC",
                recipient="0xUserD",
                value_wei=2 * 10**17,
                timestamp=now + 5000,
                block_number=4400,
            ),
        ]

        findings = self.detector.analyze_batch(txs)
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
