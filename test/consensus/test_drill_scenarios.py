"""
Task P11-011: End-to-End Consensus Attack Drill Scenarios.
Simulates concentration cartel attacks and statistical selfish mining,
verifying detection by Agents E and G, graph enrichment, OPA boundary blocks
on autonomous agent mitigations, supermajority AVS quorum routing, and
operator-authorized mitigation handoff.
"""

import hashlib
import unittest

from src.consensus.agent_consensus_client import AgentConsensusClient
from src.consensus.avs_router import ConsensusAvsRouter, RoutingVerdict
from src.consensus.bls_aggregation import BLSAggregator, ValidatorKeyring
from src.consensus.concentration_tracker import ConsensusConcentrationTracker
from src.consensus.consensus_mcp import ConsensusMcpRegistry
from src.consensus.consensus_policy import ConsensusPolicyEvaluator
from src.consensus.graph_enricher import ConsensusGraphEnricher
from src.consensus.p2p_listener import ConsensusNetworkListener
from src.consensus.reorg_monitor import ChainReorgMonitor
from src.consensus.selfish_mining_detector import SelfishMiningDetector


class TestConsensusAttackDrillScenarios(unittest.TestCase):
    def setUp(self):
        # 1. Consensus telemetry primitives
        self.p2p = ConsensusNetworkListener()
        self.reorg = ChainReorgMonitor(finality_depth=12)
        self.concentration = ConsensusConcentrationTracker()
        self.selfish = SelfishMiningDetector(min_window_for_stats=10)

        # 2. Registry, policy, and enricher
        self.registry = ConsensusMcpRegistry(
            p2p_listener=self.p2p,
            reorg_monitor=self.reorg,
            concentration_tracker=self.concentration,
            selfish_detector=self.selfish,
        )
        self.policy = ConsensusPolicyEvaluator(rego_policy_path="policy/consensus_boundary.rego")
        self.enricher = ConsensusGraphEnricher()

        # 3. 4-node validator cluster for AVS verification (threshold = 3 for >2/3 supermajority)
        self.validators = ["val-1", "val-2", "val-3", "val-4"]
        self.keyring = ValidatorKeyring()
        for v in self.validators:
            self.keyring.register_validator(v)

        self.aggregator = BLSAggregator(
            registered_validators=self.validators,
            keyring=self.keyring,
        )
        self.avs_router = ConsensusAvsRouter(bls_aggregator=self.aggregator)

        # 4. Agent clients
        self.agent_e = AgentConsensusClient("agent_e", mcp_registry=self.registry, policy_evaluator=self.policy)
        self.agent_g = AgentConsensusClient("agent_g", mcp_registry=self.registry, policy_evaluator=self.policy)

    def test_concentration_cartel_drill_scenario(self):
        # Step 1: Simulate hostile concentration breach
        self.concentration.set_explicit_distribution({
            "cartel-pool": 55.0,
            "benign-pool-a": 25.0,
            "benign-pool-b": 20.0,
        })

        # Step 2: Agent E queries network stability
        res = self.agent_e.query_network_stability()
        self.assertEqual(res["status"], "success")
        concentration_data = res["data"]["concentration"]
        self.assertEqual(concentration_data["alert_level"], "CRITICAL")
        self.assertEqual(concentration_data["top_entity_id"], "cartel-pool")

        # Step 3: Threat graph enrichment
        metrics = self.concentration.calculate_metrics()
        finding = self.enricher.enrich_concentration_metrics(metrics)
        self.assertIsNotNone(finding)
        self.assertEqual(finding.severity, "CRITICAL")
        self.assertTrue(finding.requires_avs)
        self.assertTrue(any(n.node_id == "entity-cartel-pool" for n in finding.nodes))

        # Step 4: Autonomous agent mitigation blocked by OPA policy
        with self.assertRaises(PermissionError) as ctx:
            self.agent_e.execute_tool("mitigate")
        self.assertIn("denied execution", str(ctx.exception))

        # Step 5: Multi-validator supermajority attestation (3/4 = 75% > 66.7%)
        receipt_hash = self.avs_router.derive_consensus_receipt_hash(finding.crypto_digest)
        msg_digest = self.aggregator.compute_message_digest("attest-cartel-01", finding.crypto_digest, receipt_hash)
        votes = {
            "val-1": self.keyring.sign("val-1", msg_digest),
            "val-2": self.keyring.sign("val-2", msg_digest),
            "val-3": self.keyring.sign("val-3", msg_digest),
        }
        cert = self.aggregator.aggregate_signatures(
            attestation_id="attest-cartel-01",
            finding_digest=finding.crypto_digest,
            receipt_hash=receipt_hash,
            votes=votes,
        )

        # Step 6: Route finding through AVS
        mitigation_payload = self.avs_router.route_finding(
            finding=finding,
            quorum_certificate=cert,
            receipt_hash=receipt_hash,
        )
        self.assertEqual(mitigation_payload.routing_verdict, RoutingVerdict.APPROVED)
        self.assertEqual(mitigation_payload.crypto_digest, finding.crypto_digest)

        # Step 7: Human operator authorization check
        op_auth = self.policy.evaluate(
            principal="operator",
            action="mitigate",
            resource="consensus_engine",
            token_valid=True,
        )
        self.assertTrue(op_auth.allowed)
        self.assertIn("authorized", op_auth.reason)

    def test_selfish_mining_private_release_drill_scenario(self):
        # Step 1: Feed observations into detector
        # Baseline normal blocks (10 blocks)
        for i in range(10):
            self.selfish.record_block(
                block_number=100 + i,
                block_hash=f"0xhonest{i:04x}",
                parent_hash=f"0xhonest{i-1:04x}" if i > 0 else "0xgenesis",
                miner_or_pool="pool-honest",
                is_orphaned=False,
                timestamp=1700000000.0 + i * 12.0,
                reorg_depth_caused=0,
            )
        # Anomalous streak with high orphans and private release dump by rogue pool
        for i in range(6):
            self.selfish.record_block(
                block_number=110 + i,
                block_hash=f"0xrogue{i:04x}",
                parent_hash=f"0xhonest0009",
                miner_or_pool="rogue-pool",
                is_orphaned=True,
                timestamp=1700000120.0 + i * 12.0,
                reorg_depth_caused=0,
            )
        # Private release dump (causes reorg depth >= 1)
        self.selfish.record_block(
            block_number=116,
            block_hash="0xroguedump",
            parent_hash="0xhonest0009",
            miner_or_pool="rogue-pool",
            is_orphaned=False,
            timestamp=1700000200.0,
            reorg_depth_caused=3,
        )

        # Step 2: Agent G queries consensus context
        res = self.agent_g.query_incident_consensus_context(suspected_miner="rogue-pool")
        self.assertEqual(res["status"], "success")
        selfish_data = res["data"]["selfish_mining"]
        self.assertIsNotNone(selfish_data)
        self.assertIn(selfish_data["threat_level"], ["WARNING", "CRITICAL_ATTACK"])

        # Step 3: Threat graph enrichment
        alert = self.selfish.evaluate_miner("rogue-pool")
        self.assertIsNotNone(alert)
        finding = self.enricher.enrich_selfish_mining_alert(alert)
        self.assertIsNotNone(finding)
        self.assertTrue(finding.requires_avs)
        self.assertTrue(any(e.relationship == "ATTRIBUTED_TO" for e in finding.edges))

        # Step 4: Autonomous agent mitigation blocked by OPA policy
        with self.assertRaises(PermissionError):
            self.agent_g.execute_tool("slash_validator")

        # Step 5: Multi-validator supermajority attestation
        receipt_hash = self.avs_router.derive_consensus_receipt_hash(finding.crypto_digest)
        msg_digest = self.aggregator.compute_message_digest("attest-sm-01", finding.crypto_digest, receipt_hash)
        votes = {
            "val-1": self.keyring.sign("val-1", msg_digest),
            "val-2": self.keyring.sign("val-2", msg_digest),
            "val-4": self.keyring.sign("val-4", msg_digest),
        }
        cert = self.aggregator.aggregate_signatures(
            attestation_id="attest-sm-01",
            finding_digest=finding.crypto_digest,
            receipt_hash=receipt_hash,
            votes=votes,
        )

        # Step 6: Route finding through AVS
        payload = self.avs_router.route_finding(
            finding=finding,
            quorum_certificate=cert,
            receipt_hash=receipt_hash,
        )
        self.assertEqual(payload.routing_verdict, RoutingVerdict.APPROVED)

        # Step 7: Operator authorizes handoff
        op_auth = self.policy.evaluate(
            principal="soc_lead",
            action="execute_action",
            resource="consensus_engine",
            token_valid=True,
        )
        self.assertTrue(op_auth.allowed)

    def test_unverifiable_finding_rejection_drill_continuity(self):
        # Deliberate false/hallucinated finding simulation
        fake_digest = hashlib.sha256(b"fake-alert").hexdigest()
        tampered_digest = hashlib.sha256(b"tampered-alert").hexdigest()

        # Construct finding with fake digest
        finding = self.enricher.enrich_concentration_metrics(
            self.concentration.calculate_metrics()
        )
        if finding is None:
            from src.consensus.graph_enricher import ConsensusFinding
            finding = ConsensusFinding(
                finding_id="c6-hallucinated-01",
                finding_type="CONSENSUS_CONCENTRATION",
                severity="CRITICAL",
                zone="ZONE_6_CONSENSUS",
                layer="CONSENSUS",
                title="Fake Concentration",
                description="Hallucinated attack",
                crypto_digest=fake_digest,
                requires_avs=True,
                nodes=[],
                edges=[],
                timestamp=1700000000.0,
            )

        # Create certificate bound to a DIFFERENT digest (tampered)
        receipt_hash = hashlib.sha256(b"rcpt").hexdigest()
        msg_digest = self.aggregator.compute_message_digest("attest-fake-01", tampered_digest, receipt_hash)
        votes = {
            "val-1": self.keyring.sign("val-1", msg_digest),
            "val-2": self.keyring.sign("val-2", msg_digest),
            "val-3": self.keyring.sign("val-3", msg_digest),
        }
        cert = self.aggregator.aggregate_signatures(
            attestation_id="attest-fake-01",
            finding_digest=tampered_digest,
            receipt_hash=receipt_hash,
            votes=votes,
        )

        # AVS router detects digest mismatch and rejects
        with self.assertRaises(ValueError) as ctx:
            self.avs_router.route_finding(
                finding=finding,
                quorum_certificate=cert,
                receipt_hash=receipt_hash,
            )
        self.assertIn("Certificate digest mismatch", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
