"""
Task P11-003: Unit tests for PoW/PoS Consensus Concentration Tracker.
Validates Nakamoto coefficient, HHI, single-entity and top-3 dominance metrics,
threshold warning and critical alert levels, and sliding window behaviour.
"""

import unittest

from src.consensus.concentration_tracker import (
    ConcentrationAlertLevel,
    ConsensusConcentrationTracker,
)


class TestConcentrationTracker(unittest.TestCase):
    def setUp(self):
        self.tracker = ConsensusConcentrationTracker(
            window_size=10,
            warning_single_threshold=0.33,
            critical_single_threshold=0.50,
            warning_top3_threshold=0.51,
        )

    def test_empty_tracker_returns_clear_metrics(self):
        metrics = self.tracker.calculate_metrics()
        self.assertEqual(metrics.total_entities, 0)
        self.assertEqual(metrics.nakamoto_coefficient, 0)
        self.assertEqual(metrics.hhi, 0.0)
        self.assertEqual(metrics.alert_level, ConcentrationAlertLevel.CLEAR)

    def test_decentralized_competitive_distribution(self):
        # 10 distinct entities each having 10% share
        dist = {f"validator-{i}": 10.0 for i in range(1, 11)}
        self.tracker.set_explicit_distribution(dist)

        metrics = self.tracker.calculate_metrics()
        self.assertEqual(metrics.total_entities, 10)
        # 5 * 10% = 50%, need 6th to exceed 50%
        self.assertEqual(metrics.nakamoto_coefficient, 6)
        # 10 * (10^2) = 1000 (competitive)
        self.assertEqual(metrics.hhi, 1000.0)
        self.assertEqual(metrics.max_single_share, 0.10)
        self.assertEqual(metrics.top3_cumulative_share, 0.30)
        self.assertEqual(metrics.alert_level, ConcentrationAlertLevel.CLEAR)
        self.assertEqual(len(metrics.alert_reasons), 0)

    def test_single_entity_warning_threshold_breach(self):
        # Entity 1 has 35% (> 33%), remainder split
        dist = {
            "pool-alpha": 35.0,
            "pool-beta": 20.0,
            "pool-gamma": 15.0,
            "pool-delta": 15.0,
            "pool-epsilon": 15.0,
        }
        self.tracker.set_explicit_distribution(dist)

        metrics = self.tracker.calculate_metrics()
        self.assertEqual(metrics.top_entity_id, "pool-alpha")
        self.assertEqual(metrics.max_single_share, 0.35)
        self.assertEqual(metrics.alert_level, ConcentrationAlertLevel.WARNING)
        self.assertTrue(any("BFT liveness hazard" in r for r in metrics.alert_reasons))

    def test_top3_cartel_warning_threshold_breach(self):
        # Top 3 entities hold 20% + 20% + 15% = 55% (> 51%), max single is 20% (< 33%)
        dist = {
            "miner-1": 20.0,
            "miner-2": 20.0,
            "miner-3": 15.0,
            "miner-4": 15.0,
            "miner-5": 15.0,
            "miner-6": 15.0,
        }
        self.tracker.set_explicit_distribution(dist)

        metrics = self.tracker.calculate_metrics()
        self.assertEqual(metrics.top3_cumulative_share, 0.55)
        self.assertEqual(metrics.alert_level, ConcentrationAlertLevel.WARNING)
        self.assertTrue(any("Cartel risk" in r for r in metrics.alert_reasons))

    def test_critical_majority_dominance_breach(self):
        # Single entity holds 51% (> 50%)
        dist = {
            "hostile-validator": 51.0,
            "validator-b": 25.0,
            "validator-c": 24.0,
        }
        self.tracker.set_explicit_distribution(dist)

        metrics = self.tracker.calculate_metrics()
        self.assertEqual(metrics.top_entity_id, "hostile-validator")
        self.assertEqual(metrics.max_single_share, 0.51)
        self.assertEqual(metrics.nakamoto_coefficient, 1)
        self.assertEqual(metrics.alert_level, ConcentrationAlertLevel.CRITICAL)
        self.assertTrue(any("51% safety hazard" in r for r in metrics.alert_reasons))

    def test_sliding_window_eviction(self):
        # Window size is 10
        # Feed 10 events from bad-miner
        for _ in range(10):
            self.tracker.record_production_event("bad-miner", 1.0)
        self.assertEqual(self.tracker.calculate_metrics().alert_level, ConcentrationAlertLevel.CRITICAL)

        # Feed 10 new events from diverse miners
        for i in range(10):
            self.tracker.record_production_event(f"good-miner-{i}", 1.0)

        # bad-miner should be completely evicted
        metrics = self.tracker.calculate_metrics()
        self.assertEqual(metrics.total_entities, 10)
        self.assertEqual(metrics.alert_level, ConcentrationAlertLevel.CLEAR)
        self.assertNotIn("bad-miner", [metrics.top_entity_id])


if __name__ == "__main__":
    unittest.main()
