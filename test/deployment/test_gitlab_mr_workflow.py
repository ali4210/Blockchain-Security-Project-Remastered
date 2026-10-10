"""
Task P07-005: Unit Tests for Draft GitLab Merge Request Workflow Generator.
Validates draft title enforcement, tracking labels, cryptographic provenance binding,
and JSON payload export.
"""

import json
from pathlib import Path
import tempfile
import unittest

from src.consensus.bls_aggregation import QuorumCertificate, ValidatorKeyring, BLSAggregator
from src.deployment.patch_sandbox import PatchManifest
from src.deployment.gitlab_mr_workflow import GitLabMRWorkflow, GitLabMRPayload


class TestGitLabMRWorkflow(unittest.TestCase):
    def setUp(self):
        self.workflow = GitLabMRWorkflow(target_branch="main")
        self.patch_manifest = PatchManifest(
            schemaVersion=1,
            patchId="PATCH-REENT-12345678",
            targetContract="contracts/solidity/VulnerableVault.sol",
            patchDigest="a1b2c3d4e5f60718293a4b5c6d7e8f901234567890abcdef1234567890abcdef",
            originalDigest="1111111111111111111111111111111111111111111111111111111111111111",
            patchedDigest="2222222222222222222222222222222222222222222222222222222222222222",
            unifiedDiff="--- a/contracts/solidity/VulnerableVault.sol\n+++ b/contracts/solidity/VulnerableVault.sol\n- bad\n+ good\n",
            networkIsolated=True,
            synthesizedAt="2026-10-10T00:00:00+00:00",
        )

        validators = ["validator-1", "validator-2", "validator-3"]
        keyring = ValidatorKeyring(seed="mr-test-seed")
        aggregator = BLSAggregator(validators, keyring=keyring)
        receipt_hash = "0xmockreceipthash1234567890abcdef1234567890abcdef1234567890abcdef"
        msg_digest = aggregator.compute_message_digest("ATT-CERT-001", "mock-finding-digest", receipt_hash)
        votes = {v: keyring.sign(v, msg_digest) for v in validators}
        self.certificate = aggregator.aggregate_signatures("ATT-CERT-001", "mock-finding-digest", receipt_hash, votes)

    def test_create_draft_mr_success(self):
        mr = self.workflow.create_draft_mr(
            finding_id="FINDING-REENT-001",
            target_contract="VulnerableVault",
            severity="CRITICAL",
            patch_manifest=self.patch_manifest,
            certificate=self.certificate,
        )

        self.assertIsInstance(mr, GitLabMRPayload)
        self.assertTrue(mr.draft)
        self.assertTrue(mr.title.startswith("Draft: [Remediation]"))
        self.assertIn("FINDING-REENT-001", mr.title)
        self.assertEqual(mr.target_branch, "main")
        self.assertTrue(mr.source_branch.startswith("remediation/finding-reent-001-"))

        # Verify tracking labels
        self.assertIn("security::finding", mr.labels)
        self.assertIn("remediation::swarm", mr.labels)
        self.assertIn("status::draft-review", mr.labels)
        self.assertIn("zone::deployment", mr.labels)

        # Verify description contains cryptographic bindings
        self.assertIn(self.certificate.attestation_id, mr.description)
        self.assertIn(self.patch_manifest.patchDigest, mr.description)
        self.assertIn("Pre-Merge Verification Checklist", mr.description)

    def test_invalid_patch_digest_raises_value_error(self):
        invalid_manifest = PatchManifest(
            schemaVersion=1,
            patchId="PATCH-BAD",
            targetContract="VulnerableVault",
            patchDigest="short-digest",
            originalDigest="1111",
            patchedDigest="2222",
            unifiedDiff="diff",
            networkIsolated=True,
            synthesizedAt="now",
        )

        with self.assertRaises(ValueError) as ctx:
            self.workflow.create_draft_mr(
                finding_id="FINDING-001",
                target_contract="VulnerableVault",
                severity="HIGH",
                patch_manifest=invalid_manifest,
                certificate=self.certificate,
            )
        self.assertIn("Invalid patch manifest", str(ctx.exception))

    def test_export_mr_payload_to_json(self):
        mr = self.workflow.create_draft_mr(
            finding_id="FINDING-REENT-001",
            target_contract="VulnerableVault",
            severity="CRITICAL",
            patch_manifest=self.patch_manifest,
            certificate=self.certificate,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = Path(tmpdir) / "gitlab_mr.json"
            self.workflow.export_mr_payload(mr, out_file)

            self.assertTrue(out_file.exists())
            data = json.loads(out_file.read_text(encoding="utf-8"))
            self.assertEqual(data["draft"], True)
            self.assertEqual(data["finding_id"], "FINDING-REENT-001")
            self.assertEqual(data["attestation_id"], "ATT-CERT-001")


if __name__ == "__main__":
    unittest.main()
