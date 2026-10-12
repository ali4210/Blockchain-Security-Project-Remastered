"""
Task P12-013: Unit tests for MPC Relayer Key Compromise Drill.
Validates:
1. Drill executes end-to-end deterministically.
2. Adversarial drainage triggers SimulationError.
3. Agent E quarantines the operation and sets BLOCKED_SIMULATION_FAILURE.
4. Comprehensive audit log records defense telemetry.
"""

from unittest.mock import patch
import unittest

from src.drills.drill_relayer_key_compromise import RelayerCompromiseDrill, DrillOutcome


class TestDrillRelayerCompromise(unittest.TestCase):
    def setUp(self):
        self.drill = RelayerCompromiseDrill()

    @patch("src.agents.agent_e_incident_commander.chat", return_value="[OFFLINE_FALLBACK]")
    def test_relayer_compromise_drill_blocks_drain_and_quarantines(self, _mock_chat):
        outcome: DrillOutcome = self.drill.run_drill()

        self.assertTrue(outcome.success, "Drill should report successful defense.")
        self.assertTrue(outcome.simulation_blocked, "Simulation gate must block unauthorized transaction.")
        self.assertEqual(outcome.containment_status, "BLOCKED_SIMULATION_FAILURE")
        self.assertEqual(outcome.incident_severity, "SEV-1")

        # Verify audit log fidelity
        log_text = "\n".join(outcome.audit_log)
        self.assertIn("DRILL_INIT", log_text)
        self.assertIn("ADVERSARY_ACTION", log_text)
        self.assertIn("DEFENSE_GATE", log_text)
        self.assertIn("INCIDENT_RESPONSE", log_text)
        self.assertIn("DRILL_SUCCESS", log_text)


if __name__ == "__main__":
    unittest.main()
