"""
Task P06-002: Unit and Simulation Integration Tests for Local Validator Cluster.
Tests the request handler endpoints (/health, /vote), deterministic signature generation,
and integration with the AVSGate consensus engine.
"""

from http.server import HTTPServer
import json
import threading
import time
import unittest
import urllib.request
import urllib.error

from src.consensus.validator_node import ValidatorRequestHandler
from src.consensus.avs_gate import AVSGate, ValidatorVote, VoteDecision, ConsensusStatus


class TestValidatorNodeService(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port = 18081
        ValidatorRequestHandler.validator_id = "validator-1"
        cls.server = HTTPServer(("127.0.0.1", cls.port), ValidatorRequestHandler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        time.sleep(0.05)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_health_endpoint(self):
        url = f"http://127.0.0.1:{self.port}/health"
        with urllib.request.urlopen(url, timeout=2) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data.get("status"), "healthy")
            self.assertEqual(data.get("validator_id"), "validator-1")
            self.assertEqual(data.get("network"), "local_coursework_simulation")

    def test_vote_endpoint_returns_signed_receipt(self):
        url = f"http://127.0.0.1:{self.port}/vote"
        payload = json.dumps({
            "finding_digest": "abcdef1234567890",
            "target_contract": "contracts/solidity/VulnerableVault.sol",
        }).encode("utf-8")
        req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"}, method="POST")

        with urllib.request.urlopen(req, timeout=2) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data.get("validator_id"), "validator-1")
            self.assertEqual(data.get("decision"), "VALIDATED")
            self.assertTrue(len(data.get("execution_receipt_hash", "")) > 0)
            self.assertTrue(len(data.get("signature", "")) > 0)

    def test_not_found_endpoint(self):
        url = f"http://127.0.0.1:{self.port}/nonexistent"
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(url, timeout=2)
        self.assertEqual(ctx.exception.code, 404)

    def test_three_node_cluster_consensus_integration(self):
        gate = AVSGate(registered_validators=["validator-1", "validator-2", "validator-3"])
        attestation = gate.register_finding({
            "id": "FINDING-SIM-001",
            "target_contract": "contracts/solidity/VulnerableVault.sol",
            "severity": "CRITICAL",
        })

        for v_id in ["validator-1", "validator-2", "validator-3"]:
            gate.submit_vote(
                attestation.attestation_id,
                ValidatorVote(
                    validator_id=v_id,
                    decision=VoteDecision.VALIDATED,
                    execution_receipt_hash=f"receipt-{v_id}",
                    signature=f"sig-{v_id}",
                )
            )

        res = gate.evaluate_consensus(attestation.attestation_id)
        self.assertTrue(res.supermajority_achieved)
        self.assertEqual(res.status, ConsensusStatus.AGREED)


if __name__ == "__main__":
    unittest.main()
