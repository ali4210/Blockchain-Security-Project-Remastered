"""
Task P07-007: End-to-End Integration Tests for Deployment and Abort Branches.
Exercises the entire Phase 7 deployment framework on authorized sample contracts:
VulnerableVault.sol and PromptInjectionFixture.sol.
Asserts success path, consensus rejection abort, readiness failure abort,
bytecode tamper detection, and zero-state fail-closed guarantees.
"""

import hashlib
import json
from pathlib import Path
import stat
import tempfile
import unittest

from src.consensus.avs_gate import ConsensusResult, ConsensusStatus
from src.consensus.bls_aggregation import QuorumCertificate, ValidatorKeyring, BLSAggregator
from src.deployment.consensus_deployer import (
    ConsensusDeployer,
    DeploymentPlan,
    DeploymentReceipt,
)
from src.deployment.forensic_staging_snapshot import ForensicStagingSnapshot
from src.deployment.readiness_policy_gate import (
    ReadinessPolicyGate,
    ProductionReadinessPolicy,
    AbortReasonCode,
    DeploymentAbortError,
)
from src.deployment.vault_secret_store import VaultSecretStore


class TestDeploymentE2E(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.work_dir = Path(self.tmp_dir.name)
        self.staging_dir = self.work_dir / "staging" / "forensics"
        self.abort_log = self.work_dir / "audit" / "aborts.jsonl"

        # Authorized contracts
        self.contracts = {
            "VulnerableVault": Path("contracts/solidity/VulnerableVault.sol"),
            "PromptInjectionFixture": Path("contracts/solidity/PromptInjectionFixture.sol"),
        }

        # Initialize core components
        self.validators = ["validator-1", "validator-2", "validator-3", "validator-4"]
        self.keyring = ValidatorKeyring(seed="e2e-deployment-seed-2026")
        self.aggregator = BLSAggregator(self.validators, keyring=self.keyring)
        self.vault_store = VaultSecretStore()
        self.readiness_gate = ReadinessPolicyGate(
            policy=ProductionReadinessPolicy(),
            log_path=self.abort_log,
        )
        self.deployer = ConsensusDeployer(
            aggregator=self.aggregator,
            keyring=self.keyring,
        )
        self.forensics_engine = ForensicStagingSnapshot(base_staging_dir=self.staging_dir)

    def tearDown(self):
        # Restore permissions on any frozen staging subtrees before cleanup
        for p in self.work_dir.rglob("*"):
            try:
                p.chmod(stat.S_IWRITE | stat.S_IREAD | stat.S_IXUSR)
            except Exception:
                pass
        self.tmp_dir.cleanup()

    def _compute_sha256(self, content: bytes) -> str:
        return hashlib.sha256(content).hexdigest()

    def _generate_valid_cert(self, attestation_id: str, bytecode_hash: str, receipt_hash: str) -> QuorumCertificate:
        msg_digest = self.aggregator.compute_message_digest(attestation_id, bytecode_hash, receipt_hash)
        votes = {v: self.keyring.sign(v, msg_digest) for v in self.validators}
        return self.aggregator.aggregate_signatures(attestation_id, bytecode_hash, receipt_hash, votes)

    def test_e2e_deploy_success_branch(self):
        """Validates the complete success path from consensus attestation to forensic snapshot."""
        contract_path = self.contracts["VulnerableVault"]
        self.assertTrue(contract_path.exists(), f"Sample contract {contract_path} must exist")
        contract_bytes = contract_path.read_bytes()
        bytecode_hash = self._compute_sha256(contract_bytes)
        receipt_hash = "0x" + hashlib.sha256(b"receipt-seed-vault").hexdigest()
        attestation_id = "ATT-E2E-SUCCESS-001"

        # 1. Consensus quorum certification
        cert = self._generate_valid_cert(attestation_id, bytecode_hash, receipt_hash)
        consensus_result = ConsensusResult(
            attestation_id=attestation_id,
            finding_id="FINDING-VAULT-01",
            status=ConsensusStatus.AGREED,
            total_validators=len(self.validators),
            validated_votes=len(self.validators),
            rejected_votes=0,
            inconclusive_votes=0,
            supermajority_ratio=1.0,
            supermajority_achieved=True,
            certificate=cert,
        )

        plan = DeploymentPlan(
            plan_id="PLAN-E2E-SUCCESS-VAULT",
            target_contract="VulnerableVault",
            target_network="local-anvil",
            bytecode_hash=bytecode_hash,
        )

        # 2. Production readiness gate assertion
        self.readiness_gate.evaluate_and_assert(plan, consensus_result=consensus_result)

        # 3. Vault secret acquisition
        vault_secret = self.vault_store.get_deployer_key("local-anvil", role="admin")
        self.assertTrue(vault_secret.get_raw_value().startswith("0x"))
        self.assertEqual(len(vault_secret.get_raw_value()), 66)

        # 4. Deployment dispatch
        receipt = self.deployer.deploy(plan, certificate=cert, receipt_hash=receipt_hash, role="admin")
        self.assertIsInstance(receipt, DeploymentReceipt)
        self.assertEqual(receipt.plan_id, plan.plan_id)
        self.assertEqual(receipt.certificate_attestation_id, attestation_id)
        self.assertTrue(receipt.contract_address.startswith("0x"))
        self.assertEqual(str(receipt.status.value if hasattr(receipt.status, 'value') else receipt.status), "DEPLOYED")

        # 5. Revoke credentials and zeroize
        self.vault_store.revoke_lease(vault_secret.lease_id)
        vault_secret.zeroize()

        # 6. Forensic staging bundle capture
        run_id = "E2E-RUN-001"
        receipt_dict = receipt.to_dict() if hasattr(receipt, 'to_dict') else {
            "deployment_id": receipt.deployment_id,
            "plan_id": receipt.plan_id,
            "contract_address": receipt.contract_address,
            "tx_hash": receipt.tx_hash,
            "deployer_address": receipt.deployer_address,
            "certificate_attestation_id": receipt.certificate_attestation_id,
            "status": str(receipt.status.value if hasattr(receipt.status, 'value') else receipt.status),
            "deployed_at": receipt.deployed_at,
            "plan_digest": receipt.plan_digest,
        }
        artifacts = {
            "logs/deploy.log": f"Plan {plan.plan_id} deployed at {receipt.contract_address}".encode("utf-8"),
            "receipts/deployment_receipt.json": json.dumps(receipt_dict).encode("utf-8"),
            "ast/ast_projection.json": b'{"contract": "VulnerableVault", "status": "verified"}',
            "pocs/reproduction_poc.sol": b"// Sample exploit reproduction fixture\ncontract Exploit {}",
        }
        manifest = self.forensics_engine.create_snapshot(run_id, artifacts, freeze_permissions=True)
        self.assertEqual(manifest.runId, run_id)
        self.assertEqual(len(manifest.fileDigests), 4)
        self.assertTrue(self.forensics_engine.verify_snapshot(self.staging_dir / f"run-{run_id}"))

        # Verify deployed address registered in deployer registry
        self.assertIn(receipt.deployment_id, self.deployer._deployed_contracts)
        self.assertIsNotNone(self.deployer.get_receipt(receipt.deployment_id))

    def test_e2e_consensus_rejected_abort_branch(self):
        """Validates fail-closed termination when consensus quorum rejects deployment."""
        contract_path = self.contracts["PromptInjectionFixture"]
        self.assertTrue(contract_path.exists())
        contract_bytes = contract_path.read_bytes()
        bytecode_hash = self._compute_sha256(contract_bytes)

        plan = DeploymentPlan(
            plan_id="PLAN-E2E-REJECTED",
            target_contract="PromptInjectionFixture",
            target_network="local-anvil",
            bytecode_hash=bytecode_hash,
        )

        # Rejected consensus result
        rejected_result = ConsensusResult(
            attestation_id="ATT-E2E-REJECT-001",
            finding_id="FINDING-PROMPT-01",
            status=ConsensusStatus.REJECTED,
            total_validators=4,
            validated_votes=1,
            rejected_votes=3,
            inconclusive_votes=0,
            supermajority_ratio=0.25,
            supermajority_achieved=False,
            certificate=None,
        )

        with self.assertRaises(DeploymentAbortError) as ctx:
            self.readiness_gate.evaluate_and_assert(plan, consensus_result=rejected_result)

        err = ctx.exception
        self.assertEqual(err.event.abortCode, AbortReasonCode.ERR_CONSENSUS_REJECTED)
        self.assertEqual(err.event.planId, plan.plan_id)

        # Assert audit trail persistence
        self.assertTrue(self.abort_log.exists())
        audit_content = self.abort_log.read_text(encoding="utf-8")
        self.assertIn("ERR_CONSENSUS_REJECTED", audit_content)
        self.assertIn(plan.plan_id, audit_content)

        # Assert zero-state persistence
        self.assertEqual(len(self.deployer._deployed_contracts), 0)

    def test_e2e_readiness_policy_hardware_failure_abort_branch(self):
        """Validates abort when mainnet deployment lacks configured hardware security."""
        contract_bytes = self.contracts["VulnerableVault"].read_bytes()
        bytecode_hash = self._compute_sha256(contract_bytes)
        receipt_hash = "0x" + hashlib.sha256(b"receipt-mainnet").hexdigest()
        cert = self._generate_valid_cert("ATT-MAINNET-001", bytecode_hash, receipt_hash)

        agreed_result = ConsensusResult(
            attestation_id="ATT-MAINNET-001",
            finding_id="FINDING-VAULT-02",
            status=ConsensusStatus.AGREED,
            total_validators=4,
            validated_votes=4,
            rejected_votes=0,
            inconclusive_votes=0,
            supermajority_ratio=1.0,
            supermajority_achieved=True,
            certificate=cert,
        )

        mainnet_plan = DeploymentPlan(
            plan_id="PLAN-E2E-MAINNET-FAIL",
            target_contract="VulnerableVault",
            target_network="mainnet",
            bytecode_hash=bytecode_hash,
        )

        with self.assertRaises(DeploymentAbortError) as ctx:
            self.readiness_gate.evaluate_and_assert(
                mainnet_plan,
                consensus_result=agreed_result,
                hardware_token_configured=False,
            )

        err = ctx.exception
        self.assertEqual(err.event.abortCode, AbortReasonCode.ERR_UNCONFIGURED_HARDWARE)
        self.assertEqual(len(self.deployer._deployed_contracts), 0)

    def test_e2e_bytecode_tampering_abort_branch(self):
        """Validates deployer rejection when bytecode is altered post-attestation."""
        contract_bytes = self.contracts["VulnerableVault"].read_bytes()
        bytecode_hash = self._compute_sha256(contract_bytes)
        receipt_hash = "0x" + hashlib.sha256(b"receipt-tamper").hexdigest()
        cert = self._generate_valid_cert("ATT-TAMPER-001", bytecode_hash, receipt_hash)

        # Plan with altered bytecode digest
        tampered_bytes = contract_bytes + b"\xde\xad\xbe\xef"
        tampered_hash = self._compute_sha256(tampered_bytes)

        plan = DeploymentPlan(
            plan_id="PLAN-E2E-TAMPER",
            target_contract="VulnerableVault",
            target_network="local-anvil",
            bytecode_hash=tampered_hash,
        )

        with self.assertRaises(ValueError) as ctx:
            self.deployer.deploy(plan, certificate=cert, receipt_hash=receipt_hash)

        self.assertIn("Bytecode digest mismatch", str(ctx.exception))
        # Zero state persisted
        self.assertEqual(len(self.deployer._deployed_contracts), 0)


if __name__ == "__main__":
    unittest.main()
