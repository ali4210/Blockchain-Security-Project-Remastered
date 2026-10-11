"""
Task P10B-004: Unit tests for Agent G Forensic Path Write Guardrail.
Validates that Agent G is strictly blocked from writing to sealed evidence,
vault directories, and forensics.db while allowing workspace operations.
"""

from pathlib import Path
import tempfile
import unittest

from src.mcp_middleware.agent_g_guardrail import AgentGForensicGuardrail


class TestAgentGGuardrail(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.repo_root = Path(self.tmp_dir.name).resolve()

        # Create simulated protected directories and files
        self.vault_sealed = self.repo_root / "vault" / "sealed"
        self.vault_sealed.mkdir(parents=True, exist_ok=True)
        self.sealed_file = self.vault_sealed / "ev_001_memory.raw"
        self.sealed_file.write_bytes(b"SEALED_EVIDENCE_BYTES")

        self.db_file = self.repo_root / "forensics.db"
        self.db_file.write_bytes(b"SQLITE_DB_BYTES")

        # Create safe workspace directory
        self.workspace_dir = self.repo_root / "workspace" / "remediation"
        self.workspace_dir.mkdir(parents=True, exist_ok=True)

        self.guard = AgentGForensicGuardrail(repo_root=self.repo_root)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_blocks_direct_write_to_sealed_artifact(self):
        decision = self.guard.evaluate_request(
            principal="agent_g",
            action="write_file",
            target_path=self.sealed_file,
        )
        self.assertFalse(decision.allowed)
        self.assertIn("strictly forbidden from writing to sealed evidence path", decision.reason)

        with self.assertRaises(PermissionError):
            self.guard.enforce_guard(
                principal="agent_g",
                action="write_file",
                target_path=self.sealed_file,
            )

    def test_blocks_subpath_creation_inside_vault_sealed(self):
        nested_target = self.vault_sealed / "subfolder" / "tampered.txt"
        decision = self.guard.evaluate_request(
            principal="agent_g",
            action="write",
            target_path=nested_target,
        )
        self.assertFalse(decision.allowed)

    def test_blocks_writes_to_forensics_db(self):
        decision = self.guard.evaluate_request(
            principal="agent_g",
            action="modify",
            target_path=self.db_file,
        )
        self.assertFalse(decision.allowed)

    def test_blocks_directory_traversal_attempts(self):
        # Traversal payload: ../vault/sealed/ev_001_memory.raw
        traversal_target = self.repo_root / "workspace" / ".." / "vault" / "sealed" / "ev_001_memory.raw"
        decision = self.guard.evaluate_request(
            principal="agent_g",
            action="delete",
            target_path=traversal_target,
        )
        self.assertFalse(decision.allowed)

    def test_allows_writes_to_safe_remediation_workspace(self):
        safe_target = self.workspace_dir / "patch.diff"
        decision = self.guard.evaluate_request(
            principal="agent_g",
            action="write_file",
            target_path=safe_target,
        )
        self.assertTrue(decision.allowed)

    def test_allows_read_only_actions(self):
        decision = self.guard.evaluate_request(
            principal="agent_g",
            action="read",
            target_path=self.sealed_file,
        )
        self.assertTrue(decision.allowed)


if __name__ == "__main__":
    unittest.main()
