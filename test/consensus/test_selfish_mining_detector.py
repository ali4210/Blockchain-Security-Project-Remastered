"""
Task P11-004: Unit tests for Selfish Mining Anomaly Detector.
Validates baseline statistical testing, min-window suppression,
z-score anomaly detection, and private lead dump detection.
"""

import unittest

from src.consensus.selfish_mining_detector import (
    SelfishMiningDetector,
    SelfishMiningThreatLevel,
)


class TestSelfishMiningDetector(unittest.TestCase):
    def setUp(self):
        # Baseline orphan rate = 2% (0.02), min window = 50
        self.detector = SelfishMiningDetector(
            baseline_orphan_rate=0.02,
            min_window_for_stats=50,
            z_warning_threshold=3.0,
            z_critical_threshold=5.0,
            private_release_threshold=2,
        )

    def test_insufficient_window_suppresses_alerts(self):
        # Ingest only 20 blocks
        for i in range(20):
            self.detector.record_block(
                block_number=100 + i,
                block_hash=f"0x{i:064x}",
                parent_hash=f"0x{i-1:064x}",
                miner_or_pool="pool-alpha",
                is_orphaned=(i % 2 == 0),  # very high orphan rate
                timestamp=1700000000.0 + i,
            )

        alert = self.detector.evaluate_miner("pool-alpha")
        self.assertIsNone(alert)

    def test_normal_baseline_mining_yields_no_alert(self):
        # Ingest 100 blocks with ~2% orphans (2 out of 100)
        for i in range(100):
            is_orphan = (i in [25, 75])
            self.detector.record_block(
                block_number=100 + i,
                block_hash=f"0x{i:064x}",
                parent_hash=f"0x{i-1:064x}",
                miner_or_pool="honest-pool",
                is_orphaned=is_orphan,
                timestamp=1700000000.0 + i,
            )

        alert = self.detector.evaluate_miner("honest-pool")
        self.assertIsNone(alert)

    def test_elevated_orphan_rate_triggers_z_score_warning(self):
        # For N=100, p=0.02:
        # mu = 2.0, var = 100 * 0.02 * 0.98 = 1.96, sigma = 1.40
        # For z >= 3.0: orphans >= 2.0 + 3.0 * 1.40 = 6.2 -> 7 orphans
        for i in range(100):
            is_orphan = (i < 8)  # 8 orphans
            self.detector.record_block(
                block_number=100 + i,
                block_hash=f"0x{i:064x}",
                parent_hash=f"0x{i-1:064x}",
                miner_or_pool="suspect-pool",
                is_orphaned=is_orphan,
                timestamp=1700000000.0 + i,
            )

        alert = self.detector.evaluate_miner("suspect-pool")
        self.assertIsNotNone(alert)
        self.assertEqual(alert.threat_level, SelfishMiningThreatLevel.SUSPECTED)
        self.assertGreaterEqual(alert.z_score, 3.0)
        self.assertTrue(any("elevated orphan rate" in r for r in alert.reasons))

    def test_extreme_orphan_rate_triggers_critical_attack(self):
        # 16 orphans out of 100: z = (16 - 2) / 1.40 = 10.0 >= 5.0
        for i in range(100):
            is_orphan = (i < 16)
            self.detector.record_block(
                block_number=100 + i,
                block_hash=f"0x{i:064x}",
                parent_hash=f"0x{i-1:064x}",
                miner_or_pool="attacker-pool",
                is_orphaned=is_orphan,
                timestamp=1700000000.0 + i,
            )

        alert = self.detector.evaluate_miner("attacker-pool")
        self.assertIsNotNone(alert)
        self.assertEqual(alert.threat_level, SelfishMiningThreatLevel.CRITICAL_ATTACK)
        self.assertGreaterEqual(alert.z_score, 5.0)

    def test_private_branch_dumps_trigger_alert(self):
        # Even with normal orphan counts, 2 strategic reorg dumps trigger suspicion
        for i in range(50):
            reorg_depth = 2 if i in [10, 20] else 0
            self.detector.record_block(
                block_number=100 + i,
                block_hash=f"0x{i:064x}",
                parent_hash=f"0x{i-1:064x}",
                miner_or_pool="strategic-miner",
                is_orphaned=(i == 30),  # 1 orphan out of 50
                timestamp=1700000000.0 + i,
                reorg_depth_caused=reorg_depth,
            )

        alert = self.detector.evaluate_miner("strategic-miner")
        self.assertIsNotNone(alert)
        self.assertEqual(alert.threat_level, SelfishMiningThreatLevel.SUSPECTED)
        self.assertEqual(alert.private_release_streak, 2)
        self.assertTrue(any("private branch release dumps" in r for r in alert.reasons))


if __name__ == "__main__":
    unittest.main()
