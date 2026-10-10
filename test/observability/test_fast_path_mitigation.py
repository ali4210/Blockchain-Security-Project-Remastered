"""
Task P08-007: Unit Tests for Fast-Path Mitigation Signal Payload Emitter.
Validates payload synthesis, cryptographic SHA-256 integrity verification,
confidence threshold filtering, replay prevention, and JSONL log persistence.
"""

import json
from pathlib import Path
import tempfile
import unittest

from src.observability.shadow_fork_verifier import (
    AgentEShadowVerificationReport,
    ShadowReplayOutcome,
)
from src.observability.fast_path_mitigation import (
    FastPathMitigationPayload,
    MitigationActionType,
    MitigationSignalEmitter,
)


class TestFastPathMitigation(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.log_path = Path(self.temp_dir.name) / "test_mitigation_signals.jsonl"
        self.emitter = MitigationSignalEmitter(
            audit_log_path=str(self.log_path),
            min_confidence_threshold=0.80,
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_payload_integrity_verification(self):
        payload = FastPathMitigationPayload.create(
            finding_id="RASP-EXPLOIT-001",
            target_contract="0x1111111111111111111111111111111111111111",
            action=MitigationActionType.PAUSE_TARGET_CONTRACT,
            confidence_score=0.95,
            trigger_reason="Drain confirmed",
        )

        self.assertTrue(payload.verify_integrity())

        # Tamper payload
        tampered = FastPathMitigationPayload(
            schema_version=payload.schema_version,
            signal_id=payload.signal_id,
            finding_id=payload.finding_id,
            target_contract="0x2222222222222222222222222222222222222222",  # Tampered contract
            action=payload.action,
            confidence_score=payload.confidence_score,
            trigger_reason=payload.trigger_reason,
            nonce=payload.nonce,
            emitted_at=payload.emitted_at,
            payload_digest=payload.payload_digest,
        )
        self.assertFalse(tampered.verify_integrity())

    def test_emit_from_shadow_report_success(self):
        report = AgentEShadowVerificationReport(
            finding_id="RASP-EXPLOIT-002",
            target="VulnerableVault",
            outcome=ShadowReplayOutcome.CONFIRMED_EXPLOIT,
            severity_level="SEV-1",
            containment_status="IMMEDIATE_ACTION_REQUIRED",
            playbook_actions=["TRIGGER_PAUSE_CIRCUIT_BREAKER"],
            execution_trace={"balance_delta_wei": -10_000_000, "gas_used": 150000},
            audit_record_digest="a" * 64,
        )

        payload = self.emitter.emit_from_shadow_report(
            report=report,
            target_contract="0x1111111111111111111111111111111111111111",
            preferred_action=MitigationActionType.PAUSE_TARGET_CONTRACT,
        )

        self.assertIsNotNone(payload)
        self.assertEqual(payload.action, MitigationActionType.PAUSE_TARGET_CONTRACT)
        self.assertEqual(payload.finding_id, "RASP-EXPLOIT-002")
        self.assertGreaterEqual(payload.confidence_score, 0.90)

        # Check file persistence
        lines = self.log_path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 1)
        record = json.loads(lines[0])
        self.assertEqual(record["signal_id"], payload.signal_id)
        self.assertEqual(record["payload_digest"], payload.payload_digest)

    def test_emit_from_benign_report_filtered(self):
        report = AgentEShadowVerificationReport(
            finding_id="RASP-BENIGN-001",
            target="VulnerableVault",
            outcome=ShadowReplayOutcome.EXECUTION_CLEAN,
            severity_level="SEV-4",
            containment_status="MONITORING_ONLY",
            playbook_actions=["LOG_TELEMETRY"],
            execution_trace={"balance_delta_wei": 0, "gas_used": 21000},
            audit_record_digest="b" * 64,
        )

        payload = self.emitter.emit_from_shadow_report(
            report=report,
            target_contract="0x1111111111111111111111111111111111111111",
        )
        self.assertIsNone(payload)
        self.assertFalse(self.log_path.exists())

    def test_replay_attack_prevention(self):
        payload = FastPathMitigationPayload.create(
            finding_id="RASP-REPLAY-001",
            target_contract="0x3333333333333333333333333333333333333333",
            action=MitigationActionType.ISOLATE_RPC_INGEST,
            confidence_score=0.92,
            trigger_reason="RPC flood",
        )

        self.assertTrue(self.emitter.dispatch(payload))

        # Re-dispatch same payload with identical nonce
        with self.assertRaises(ValueError) as ctx:
            self.emitter.dispatch(payload)
        self.assertIn("Replay detected", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
