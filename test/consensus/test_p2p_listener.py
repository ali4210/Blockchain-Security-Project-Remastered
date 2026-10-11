"""
Task P11-001: Unit tests for Consensus P2P and Mempool Listener.
Validates mempool ingestion, propagation delay calculation, peer topology metrics,
ASN distribution aggregation, and block arrival delta capture.
"""

from datetime import datetime, timezone
import unittest

from src.consensus.p2p_listener import (
    BlockPropagationEvent,
    ConsensusNetworkListener,
    MempoolTx,
    PeerInfo,
)


class TestP2PListener(unittest.TestCase):
    def setUp(self):
        self.listener = ConsensusNetworkListener(max_mempool_cache=100, max_peer_cache=10)

    def test_record_and_query_mempool_tx_propagation_delay(self):
        t0 = 1700000000.000
        t1 = 1700000000.125  # 125 ms later

        tx = self.listener.record_mempool_transaction(
            tx_hash="0x" + "a" * 64,
            from_address="0x" + "1" * 40,
            to_address="0x" + "2" * 40,
            gas_price=50000000000,
            value_wei=1000000000000000000,
            data_payload="0xa9059cbb",
            first_seen_timestamp=t0,
            received_timestamp=t1,
        )

        self.assertEqual(tx.tx_hash, "0x" + "a" * 64)
        self.assertEqual(tx.propagation_delay_ms, 125.0)

        retrieved = self.listener.get_mempool_transaction("0x" + "a" * 64)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.gas_price, 50000000000)

    def test_rejects_invalid_tx_hash_and_future_timestamp(self):
        with self.assertRaises(ValueError):
            self.listener.record_mempool_transaction(
                tx_hash="0x123",  # invalid length
                from_address="0x" + "1" * 40,
                to_address="0x" + "2" * 40,
                gas_price=10,
                value_wei=0,
                data_payload="",
                first_seen_timestamp=1700000000.0,
            )

        with self.assertRaises(ValueError):
            # first_seen in future compared to received
            self.listener.record_mempool_transaction(
                tx_hash="0x" + "b" * 64,
                from_address="0x" + "1" * 40,
                to_address="0x" + "2" * 40,
                gas_price=10,
                value_wei=0,
                data_payload="",
                first_seen_timestamp=1700000010.0,
                received_timestamp=1700000000.0,
            )

    def test_peer_registration_and_topology_summary(self):
        # Register 4 peers across 2 ASNs and 3 subnets
        self.listener.register_peer(
            peer_id="peer-1",
            ip_addr="198.51.100.10",
            port=30303,
            asn=13335,  # Cloudflare
            client_version="Geth/v1.14.0",
            latency_rtt_ms=25.4,
        )
        self.listener.register_peer(
            peer_id="peer-2",
            ip_addr="198.51.100.22",
            port=30303,
            asn=13335,  # Cloudflare same subnet
            client_version="Geth/v1.14.0",
            latency_rtt_ms=30.1,
        )
        self.listener.register_peer(
            peer_id="peer-3",
            ip_addr="203.0.113.5",
            port=30303,
            asn=16509,  # Amazon
            client_version="Besu/v24.1.0",
            latency_rtt_ms=45.8,
        )
        self.listener.register_peer(
            peer_id="peer-4",
            ip_addr="192.0.2.1",
            port=30303,
            asn=13335,  # Cloudflare different subnet
            client_version="Nethermind/v1.25.0",
            latency_rtt_ms=18.2,
        )

        summary = self.listener.get_topology_summary()
        self.assertEqual(summary["total_peers"], 4)
        self.assertEqual(summary["unique_asns"], 2)
        self.assertEqual(summary["unique_subnets"], 3)
        self.assertEqual(summary["asn_distribution"][13335], 3)
        self.assertEqual(summary["asn_distribution"][16509], 1)
        # Max single ASN share: 3/4 = 0.75
        self.assertEqual(summary["max_single_asn_share"], 0.75)

    def test_peer_disconnect(self):
        self.listener.register_peer(
            peer_id="peer-temp",
            ip_addr="198.51.100.99",
            port=30303,
            asn=12345,
            client_version="Geth/v1.14.0",
            latency_rtt_ms=15.0,
        )
        self.assertTrue(self.listener.disconnect_peer("peer-temp"))
        self.assertFalse(self.listener.disconnect_peer("peer-temp"))
        summary = self.listener.get_topology_summary()
        self.assertEqual(summary["total_peers"], 0)

    def test_record_block_propagation_event(self):
        event = self.listener.record_block_propagation(
            block_number=20500100,
            block_hash="0x" + "c" * 64,
            parent_hash="0x" + "d" * 64,
            announced_timestamp=1700000000.0,
            received_timestamp=1700000000.350,
            peer_id="peer-1",
        )
        self.assertEqual(event.block_number, 20500100)
        self.assertEqual(event.arrival_delta_ms, 350.0)


if __name__ == "__main__":
    unittest.main()
