"""
Task P08-006: Unit Tests for Continuous Telemetry Emissions.
Validates Prometheus metric increments and ECS security log formatting
across deployment success, deployment abort, quorum updates, and RASP mitigations.
"""

import unittest
from unittest.mock import MagicMock

from src.deployment.consensus_deployer import DeploymentPlan, DeploymentReceipt, DeploymentStatus
from src.deployment.readiness_policy_gate import DeploymentAbortEvent, AbortReasonCode
from src.observability.lifecycle_telemetry import LifecycleTelemetryEmitter


class TestLifecycleTelemetryEmitter(unittest.TestCase):
    def setUp(self):
        self.mock_prom = MagicMock()
        self.mock_ecs = MagicMock()
        self.emitter = LifecycleTelemetryEmitter(
            prom_collector=self.mock_prom,
            ecs_formatter=self.mock_ecs,
        )

    def test_record_deploy_success_emission(self):
        plan = DeploymentPlan(
            plan_id="PLAN-2026-001",
            target_contract="VulnerableVault",
            target_network="hardhat-mainnet",
            bytecode_hash="0xabcdef123456",
        )
        receipt = DeploymentReceipt(
            deployment_id="DEP-2026-001",
            plan_id="PLAN-2026-001",
            contract_address="0x1111111111111111111111111111111111111111",
            tx_hash="0x9999999999999999999999999999999999999999",
            deployer_address="0xvaultdeployer",
            certificate_attestation_id="QC-ATTEST-001",
            status=DeploymentStatus.DEPLOYED,
            deployed_at="2026-10-10T12:00:00Z",
            plan_digest="a" * 64,
        )

        self.mock_ecs.format_event.return_value = {
            "event": {"category": "deployment", "outcome": "success"},
            "message": "CONTRACT_DEPLOYMENT_SUCCESS",
        }

        log = self.emitter.record_deploy_success(plan, receipt, network="hardhat-mainnet")

        # Verify Prometheus call
        self.mock_prom.record_deploy.assert_called_once_with(
            target="VulnerableVault", network="hardhat-mainnet"
        )
        # Verify ECS formatter call
        self.mock_ecs.format_event.assert_called_once()
        self.assertEqual(log["event"]["outcome"], "success")
        self.assertEqual(len(self.emitter.emitted_logs), 1)

    def test_record_deploy_abort_emission_consensus_rejected(self):
        abort_event = DeploymentAbortEvent(
            schemaVersion=1,
            eventType="DEPLOYMENT_ABORT_EVENT",
            planId="PLAN-2026-002",
            targetContract="VulnerableVault",
            targetNetwork="hardhat-mainnet",
            abortCode=AbortReasonCode.ERR_CONSENSUS_REJECTED,
            reason="Consensus rejected by validators",
            timestamp="2026-10-10T12:00:00Z",
            eventDigest="d" * 64,
        )

        self.mock_ecs.format_event.return_value = {
            "event": {"category": "deployment", "outcome": "failure"},
            "message": "DEPLOYMENT_PIPELINE_ABORTED",
        }

        log = self.emitter.record_deploy_abort(abort_event, network="hardhat-mainnet")

        self.mock_prom.record_abort.assert_called_once_with(
            reason=AbortReasonCode.ERR_CONSENSUS_REJECTED.value,
            target="VulnerableVault",
        )
        self.mock_ecs.format_event.assert_called_once()
        self.assertEqual(log["event"]["outcome"], "failure")

    def test_record_deploy_abort_emission_hardware_violation(self):
        abort_event = DeploymentAbortEvent(
            schemaVersion=1,
            eventType="DEPLOYMENT_ABORT_EVENT",
            planId="PLAN-2026-003",
            targetContract="PromptInjectionFixture",
            targetNetwork="hardhat-mainnet",
            abortCode=AbortReasonCode.ERR_UNCONFIGURED_HARDWARE,
            reason="Hardware key missing",
            timestamp="2026-10-10T12:00:00Z",
            eventDigest="e" * 64,
        )

        self.mock_ecs.format_event.return_value = {
            "event": {"category": "deployment", "outcome": "failure"},
        }

        self.emitter.record_deploy_abort(abort_event)

        self.mock_prom.record_abort.assert_called_once_with(
            reason=AbortReasonCode.ERR_UNCONFIGURED_HARDWARE.value,
            target="PromptInjectionFixture",
        )

    def test_record_quorum_update_emission(self):
        self.emitter.record_quorum_update(network="ethereum-mainnet", quorum_ratio=0.85)
        self.mock_prom.record_quorum_ratio.assert_called_once_with(
            network="ethereum-mainnet", ratio=0.85
        )

    def test_record_rasp_mitigation_emission(self):
        self.mock_ecs.format_event.return_value = {
            "event": {"category": "security", "outcome": "success"},
        }

        log = self.emitter.record_rasp_mitigation(
            finding_id="RASP-EXPLOIT-01",
            target_contract="0x1111111111111111111111111111111111111111",
            action="PAUSE_CIRCUIT_BREAKER",
            network="mainnet",
        )

        self.mock_prom.record_rasp_finding.assert_called_once_with(
            target="0x1111111111111111111111111111111111111111",
            finding_id="RASP-EXPLOIT-01",
        )
        self.mock_ecs.format_event.assert_called_once()
        self.assertEqual(log["event"]["category"], "security")

    def test_fail_safe_exception_handling(self):
        # Force exceptions on both Prometheus and ECS formatter
        self.mock_prom.record_deploy.side_effect = RuntimeError("Prometheus Connection Timeout")
        self.mock_ecs.format_event.side_effect = RuntimeError("Disk Full")

        plan = DeploymentPlan(
            plan_id="PLAN-2026-FAILSAFE",
            target_contract="VulnerableVault",
            target_network="testnet",
            bytecode_hash="0x11",
        )
        receipt = DeploymentReceipt(
            deployment_id="DEP-2026-FAILSAFE",
            plan_id="PLAN-2026-FAILSAFE",
            contract_address="0x22",
            tx_hash="0x33",
            deployer_address="0x44",
            certificate_attestation_id="QC-55",
            status=DeploymentStatus.DEPLOYED,
            deployed_at="2026-10-10T12:00:00Z",
            plan_digest="b" * 64,
        )

        # Must not raise an exception
        log = self.emitter.record_deploy_success(plan, receipt)
        self.assertEqual(log, {})


if __name__ == "__main__":
    unittest.main()
