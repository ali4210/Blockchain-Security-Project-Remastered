"""
Task P08-004: Unit Tests for Agent E Shadow-Fork Verifier & Network Logging.
Validates isolated transaction replay, exploit confirmation, Agent E incident report
synthesis, persistent append-only network logs, and SHA-256 audit digest generation.
"""

import json
from pathlib import Path
import tempfile
import unittest

from src.observability.rasp_shield import (
    RaspFinding,
    ThreatSeverity,
    ThreatSignal,
    ThreatSignalSource,
)
from src.observability.shadow_fork_verifier import (
    ShadowForkConfig,
    ShadowForkVerifier,
    ShadowExecutionTrace,
    ShadowReplayOutcome,
    AgentEShadowVerificationReport,
)


class TestShadowForkVerifier(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.log_path = Path(self.temp_dir.name) / "test_shadow_logs.jsonl"
        self.config = ShadowForkConfig(audit_log_path=str(self.log_path))
        self.verifier = ShadowForkVerifier(config=self.config)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_benign_shadow_replay(self):
        finding = RaspFinding(
            finding_id="RASP-BENIGN-001",
            target_contract="0x1111111111111111111111111111111111111111",
            tx_hash="0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            severity=ThreatSeverity.LOW,
            risk_score=0.1,
            signals=[],
            is_suspicious=False,
        )

        report = self.verifier.verify_rasp_finding(finding, target_name="VulnerableVault")
        self.assertIsInstance(report, AgentEShadowVerificationReport)
        self.assertEqual(report.outcome, ShadowReplayOutcome.EXECUTION_CLEAN)
        self.assertEqual(report.severity_level, "SEV-4")
        self.assertEqual(report.containment_status, "MONITORING_ONLY")
        self.assertTrue(self.log_path.exists())

    def test_exploit_shadow_replay_confirms_sev1(self):
        signal = ThreatSignal(
            source=ThreatSignalSource.RPC_TRACE,
            severity=ThreatSeverity.HIGH,
            indicator="ABNORMAL_CALL_DEPTH",
            details={"call_depth": 7},
        )
        finding = RaspFinding(
            finding_id="RASP-EXPLOIT-001",
            target_contract="0x2222222222222222222222222222222222222222",
            tx_hash="0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            severity=ThreatSeverity.CRITICAL,
            risk_score=0.95,
            signals=[signal],
            is_suspicious=True,
        )

        report = self.verifier.verify_rasp_finding(finding, target_name="VulnerableVault")
        self.assertEqual(report.outcome, ShadowReplayOutcome.CONFIRMED_EXPLOIT)
        self.assertEqual(report.severity_level, "SEV-1")
        self.assertEqual(report.containment_status, "IMMEDIATE_ACTION_REQUIRED")
        self.assertIn("TRIGGER_PAUSE_CIRCUIT_BREAKER", report.playbook_actions)
        self.assertLess(report.execution_trace["balance_delta_wei"], 0)

        # Verify persistent log entry
        lines = self.log_path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 1)
        entry = json.loads(lines[0])
        self.assertEqual(entry["record_digest"], report.audit_record_digest)
        self.assertEqual(entry["payload"]["finding_id"], "RASP-EXPLOIT-001")
        self.assertEqual(entry["payload"]["outcome"], "CONFIRMED_EXPLOIT")

    def test_custom_replay_executor_divergence(self):
        def custom_executor(target, tx, params):
            return ShadowExecutionTrace(
                tx_hash=tx,
                target_contract=target,
                caller=params.get("from", "0x0"),
                success=False,
                gas_used=50_000,
                balance_delta_wei=0,
                state_mutations_count=1,
                revert_reason="INVARIANT_VIOLATION",
                outcome=ShadowReplayOutcome.STATE_DIVERGENCE,
            )

        divergence_verifier = ShadowForkVerifier(
            config=self.config,
            replay_executor=custom_executor,
        )

        finding = RaspFinding(
            finding_id="RASP-DIV-001",
            target_contract="0x3333333333333333333333333333333333333333",
            tx_hash="0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            severity=ThreatSeverity.MEDIUM,
            risk_score=0.4,
            signals=[],
            is_suspicious=False,
        )

        report = divergence_verifier.verify_rasp_finding(finding, target_name="PromptInjectionFixture")
        self.assertEqual(report.outcome, ShadowReplayOutcome.STATE_DIVERGENCE)
        self.assertEqual(report.execution_trace["revert_reason"], "INVARIANT_VIOLATION")

    def test_persistent_log_record_hashing_integrity(self):
        payload = {"event": "TEST_SHADOW_REPLAY", "block": 19000000}
        digest1 = self.verifier.record_network_log(payload)
        digest2 = self.verifier.record_network_log(payload)
        self.assertEqual(digest1, digest2)  # Deterministic payload hash

        lines = self.log_path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 2)
        entry = json.loads(lines[0])
        self.assertIn("recorded_at", entry)
        self.assertEqual(entry["payload"]["event"], "TEST_SHADOW_REPLAY")


if __name__ == "__main__":
    unittest.main()
