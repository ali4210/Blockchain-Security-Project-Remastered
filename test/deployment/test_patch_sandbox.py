"""
Task P07-004: Unit and Integration Tests for Offline Patch Sandbox.
Validates air-gap isolation enforcement, path confinement, traversal prevention,
cryptographic diff hashing, and canonical PatchManifest generation.
"""

from pathlib import Path
import unittest

from src.deployment.patch_sandbox import (
    PatchSandbox,
    PatchManifest,
    PatchIsolationViolation,
)


class TestPatchSandbox(unittest.TestCase):
    def setUp(self):
        self.sandbox = PatchSandbox(offline_mode=True)
        self.target_path = "contracts/solidity/VulnerableVault.sol"
        self.original_code = (
            "// SPDX-License-Identifier: MIT\n"
            "pragma solidity ^0.8.24;\n\n"
            "contract VulnerableVault {\n"
            "    mapping(address => uint256) public balances;\n"
            "    function withdraw() public {\n"
            "        (bool s, ) = msg.sender.call{value: balances[msg.sender]}(\"\");\n"
            "        require(s);\n"
            "        balances[msg.sender] = 0;\n"
            "    }\n"
            "}\n"
        )
        self.patched_code = (
            "// SPDX-License-Identifier: MIT\n"
            "pragma solidity ^0.8.24;\n\n"
            "contract VulnerableVault {\n"
            "    mapping(address => uint256) public balances;\n"
            "    function withdraw() public {\n"
            "        uint256 amount = balances[msg.sender];\n"
            "        balances[msg.sender] = 0;\n"
            "        (bool s, ) = msg.sender.call{value: amount}(\"\");\n"
            "        require(s);\n"
            "    }\n"
            "}\n"
        )

    def test_offline_patch_generation_success(self):
        manifest = self.sandbox.generate_remediation_patch(
            target_contract_rel_path=self.target_path,
            original_source=self.original_code,
            remediated_source=self.patched_code,
            remediation_id="REENTRANCY-FIX-01",
        )

        self.assertIsInstance(manifest, PatchManifest)
        self.assertEqual(manifest.schemaVersion, 1)
        self.assertTrue(manifest.patchId.startswith("PATCH-REENTRANCY-FIX-01-"))
        self.assertTrue(manifest.networkIsolated)
        self.assertEqual(manifest.targetContract, self.target_path)
        self.assertEqual(len(manifest.patchDigest), 64)
        self.assertIn("--- a/contracts/solidity/VulnerableVault.sol", manifest.unifiedDiff)
        self.assertIn("+++ b/contracts/solidity/VulnerableVault.sol", manifest.unifiedDiff)
        self.assertIn("-        balances[msg.sender] = 0;", manifest.unifiedDiff)
        self.assertIn("+        uint256 amount = balances[msg.sender];", manifest.unifiedDiff)

    def test_network_enabled_violates_isolation(self):
        online_sandbox = PatchSandbox(offline_mode=False)
        with self.assertRaises(PatchIsolationViolation) as ctx:
            online_sandbox.generate_remediation_patch(
                target_contract_rel_path=self.target_path,
                original_source=self.original_code,
                remediated_source=self.patched_code,
                remediation_id="REENTRANCY-FIX-01",
            )
        self.assertIn("network isolation is disabled", str(ctx.exception))

    def test_path_traversal_attempt_rejected(self):
        traversal_path = "contracts/solidity/../../package.json"
        with self.assertRaises(PatchIsolationViolation) as ctx:
            self.sandbox.generate_remediation_patch(
                target_contract_rel_path=traversal_path,
                original_source=self.original_code,
                remediated_source=self.patched_code,
                remediation_id="TRAVERSAL-ATTEMPT",
            )
        self.assertIn("Path traversal detected", str(ctx.exception))

    def test_unauthorized_directory_path_rejected(self):
        unauthorized_path = "config/hardhat.config.js"
        with self.assertRaises(PatchIsolationViolation) as ctx:
            self.sandbox.generate_remediation_patch(
                target_contract_rel_path=unauthorized_path,
                original_source=self.original_code,
                remediated_source=self.patched_code,
                remediation_id="CONFIG-TAMPER",
            )
        self.assertIn("outside approved root directories", str(ctx.exception))

    def test_identical_source_raises_value_error(self):
        with self.assertRaises(ValueError) as ctx:
            self.sandbox.generate_remediation_patch(
                target_contract_rel_path=self.target_path,
                original_source=self.original_code,
                remediated_source=self.original_code,
                remediation_id="NOOP-FIX",
            )
        self.assertIn("identical to original", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
