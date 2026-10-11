"""
Task P11-002: Unit tests for Chain Reorganization Monitor.
Validates linear extension, micro-fork detection, deep reorg anomalies,
critical finality depth violations, and orphaned block tracking.
"""

import unittest

from src.consensus.reorg_monitor import (
    BlockHeaderRecord,
    ChainReorgMonitor,
    ReorgSeverity,
)


class TestReorgMonitor(unittest.TestCase):
    def setUp(self):
        # Configure with finality depth = 12
        self.monitor = ChainReorgMonitor(finality_depth=12)

        # Genesis anchor at block 100
        self.anchor = BlockHeaderRecord(
            block_number=100,
            block_hash="0x" + "0" * 63 + "a",
            parent_hash="0x" + "0" * 64,
            timestamp=1700000000.0,
            miner_or_validator="genesis",
        )
        self.monitor.initialize_anchor(self.anchor)

    def test_linear_canonical_chain_extension_no_reorg(self):
        prev = self.anchor.block_hash
        for n in range(101, 105):
            h = BlockHeaderRecord(
                block_number=n,
                block_hash=f"0x{n:064x}",
                parent_hash=prev,
                timestamp=1700000000.0 + (n - 100) * 12.0,
            )
            event = self.monitor.process_header(h)
            self.assertIsNone(event)
            prev = h.block_hash

        self.assertEqual(self.monitor.canonical_tip_number, 104)
        self.assertEqual(len(self.monitor.get_canonical_chain()), 5)

    def test_micro_fork_detection_depth_1(self):
        # Build 101a
        h101a = BlockHeaderRecord(
            block_number=101,
            block_hash="0x" + "1" * 64,
            parent_hash=self.anchor.block_hash,
            timestamp=1700000012.0,
        )
        self.monitor.process_header(h101a)
        self.assertEqual(self.monitor.canonical_tip_hash, h101a.block_hash)

        # Build competitor branch 101b -> 102b
        h101b = BlockHeaderRecord(
            block_number=101,
            block_hash="0x" + "2" * 64,
            parent_hash=self.anchor.block_hash,
            timestamp=1700000012.1,
        )
        event1 = self.monitor.process_header(h101b)
        self.assertIsNone(event1)  # Height equal to current tip (101), no reorg yet

        h102b = BlockHeaderRecord(
            block_number=102,
            block_hash="0x" + "3" * 64,
            parent_hash=h101b.block_hash,
            timestamp=1700000024.0,
        )
        event2 = self.monitor.process_header(h102b)
        self.assertIsNotNone(event2)
        self.assertEqual(event2.reorg_depth, 1)
        self.assertEqual(event2.severity, ReorgSeverity.MICRO_FORK)
        self.assertEqual(event2.common_ancestor_hash, self.anchor.block_hash)
        self.assertEqual(event2.orphaned_block_hashes, [h101a.block_hash])
        self.assertEqual(event2.new_canonical_tip, h102b.block_hash)

    def test_deep_reorg_anomaly_detection(self):
        # Build canonical chain 101 to 108 (depth 8 from anchor)
        curr = self.anchor.block_hash
        canonical_hashes = []
        for n in range(101, 109):
            h = BlockHeaderRecord(
                block_number=n,
                block_hash=f"0x{n:062x}aa",
                parent_hash=curr,
                timestamp=1700000000.0 + n,
            )
            self.monitor.process_header(h)
            curr = h.block_hash
            canonical_hashes.append(curr)

        self.assertEqual(self.monitor.canonical_tip_number, 108)

        # Secret branch splitting off at block 102 (depth 6 reorg: blocks 103..108 orphaned)
        # Fork branch builds 103b to 109b (length 7, overtaking height 108)
        split_ancestor = canonical_hashes[1]  # block 102
        curr_fork = split_ancestor
        for n in range(103, 110):
            h_fork = BlockHeaderRecord(
                block_number=n,
                block_hash=f"0x{n:062x}ff",
                parent_hash=curr_fork,
                timestamp=1700000000.0 + n,
            )
            event = self.monitor.process_header(h_fork)
            curr_fork = h_fork.block_hash
            if n < 109:
                self.assertIsNone(event)
            else:
                # n=109 outgrows canonical height 108 -> triggers reorg
                self.assertIsNotNone(event)
                self.assertEqual(event.reorg_depth, 6)
                self.assertEqual(event.severity, ReorgSeverity.DEEP_REORG_ANOMALY)
                self.assertEqual(event.common_ancestor_number, 102)
                self.assertEqual(len(event.orphaned_block_hashes), 6)

    def test_critical_finality_violation_depth_at_or_above_finality(self):
        # Build canonical chain 101 to 115 (15 blocks after anchor)
        curr = self.anchor.block_hash
        for n in range(101, 116):
            h = BlockHeaderRecord(
                block_number=n,
                block_hash=f"0x{n:062x}11",
                parent_hash=curr,
                timestamp=1700000000.0 + n,
            )
            self.monitor.process_header(h)
            curr = h.block_hash

        # Attacker branches from anchor (100) and produces 16 blocks (101b..116b)
        # Reorg depth is 15 >= finality_depth (12)
        curr_attack = self.anchor.block_hash
        for n in range(101, 117):
            h_attack = BlockHeaderRecord(
                block_number=n,
                block_hash=f"0x{n:062x}99",
                parent_hash=curr_attack,
                timestamp=1700000000.0 + n,
            )
            event = self.monitor.process_header(h_attack)
            curr_attack = h_attack.block_hash
            if n < 116:
                self.assertIsNone(event)
            else:
                self.assertIsNotNone(event)
                self.assertEqual(event.reorg_depth, 15)
                self.assertEqual(event.severity, ReorgSeverity.CRITICAL_FINALITY_VIOLATION)

    def test_rejects_disconnected_orphan_lineage(self):
        disconnected = BlockHeaderRecord(
            block_number=200,
            block_hash="0x" + "f" * 64,
            parent_hash="0x" + "e" * 64,  # parent unknown
            timestamp=1700000000.0,
        )
        with self.assertRaises(ValueError) as ctx:
            self.monitor.process_header(disconnected)
        self.assertIn("Disconnected block lineage", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
