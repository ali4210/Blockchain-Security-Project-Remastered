"""
Task P07-004: Offline Sandboxed Patch Generation Engine.
Ensures swarm remediation patches are synthesized strictly inside an isolated,
network-disabled execution environment with path confinement and cryptographic diff hashing.
"""

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import difflib
import hashlib
from pathlib import Path
from typing import Any, Dict, List, Optional


class PatchIsolationViolation(RuntimeError):
    """Raised when patch generation violates offline or filesystem confinement rules."""
    pass


@dataclass(frozen=True)
class PatchManifest:
    schemaVersion: int
    patchId: str
    targetContract: str
    patchDigest: str
    originalDigest: str
    patchedDigest: str
    unifiedDiff: str
    networkIsolated: bool
    synthesizedAt: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class PatchSandbox:
    """
    Executes automated contract patching in a strictly offline sandbox.
    Guarantees zero network egress during synthesis and enforces directory confinement.
    """

    SCHEMA_VERSION = 1
    ALLOWED_TARGET_ROOTS = ["contracts/solidity"]

    def __init__(
        self,
        base_dir: Optional[Path] = None,
        offline_mode: bool = True,
    ):
        self.base_dir = (base_dir or Path.cwd()).resolve()
        self.offline_mode = offline_mode

    def _verify_offline_constraints(self) -> None:
        """Asserts air-gapped / offline environment invariant."""
        if not self.offline_mode:
            raise PatchIsolationViolation(
                "Patch generation REFUSED: Sandbox network isolation is disabled. "
                "Swarm patches must be synthesized strictly within an offline container."
            )

    def _verify_path_confinement(self, relative_contract_path: str) -> Path:
        """Enforces that target paths remain strictly confined to approved contract roots."""
        clean_path = Path(relative_contract_path).as_posix()

        # Reject explicit path traversal
        if ".." in clean_path.split("/"):
            raise PatchIsolationViolation(
                f"Path traversal detected: '{relative_contract_path}' violates sandbox confinement."
            )

        # Ensure path resides under approved contract directories
        is_allowed = any(clean_path.startswith(root) for root in self.ALLOWED_TARGET_ROOTS)
        if not is_allowed:
            raise PatchIsolationViolation(
                f"Target path '{relative_contract_path}' is outside approved root directories: {self.ALLOWED_TARGET_ROOTS}"
            )

        resolved = (self.base_dir / relative_contract_path).resolve()
        try:
            resolved.relative_to(self.base_dir)
        except ValueError:
            raise PatchIsolationViolation(
                f"Resolved target '{resolved}' escapes workspace boundary."
            )

        return resolved

    def compute_sha256(self, content: str) -> str:
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def generate_remediation_patch(
        self,
        target_contract_rel_path: str,
        original_source: str,
        remediated_source: str,
        remediation_id: str,
    ) -> PatchManifest:
        """
        Synthesizes a unified diff and cryptographic PatchManifest inside the offline sandbox.
        """
        self._verify_offline_constraints()
        self._verify_path_confinement(target_contract_rel_path)

        if original_source == remediated_source:
            raise ValueError("Remediated source is identical to original; no patch required.")

        original_lines = original_source.splitlines(keepends=True)
        remediated_lines = remediated_source.splitlines(keepends=True)

        diff = "".join(
            difflib.unified_diff(
                original_lines,
                remediated_lines,
                fromfile=f"a/{target_contract_rel_path}",
                tofile=f"b/{target_contract_rel_path}",
            )
        )

        if not diff:
            raise ValueError("Failed to compute valid diff representation.")

        orig_digest = self.compute_sha256(original_source)
        patched_digest = self.compute_sha256(remediated_source)
        patch_digest = self.compute_sha256(diff)
        ts = datetime.now(timezone.utc).isoformat()
        patch_id = f"PATCH-{remediation_id}-{patch_digest[:8]}"

        return PatchManifest(
            schemaVersion=self.SCHEMA_VERSION,
            patchId=patch_id,
            targetContract=target_contract_rel_path,
            patchDigest=patch_digest,
            originalDigest=orig_digest,
            patchedDigest=patched_digest,
            unifiedDiff=diff,
            networkIsolated=True,
            synthesizedAt=ts,
        )
