"""
Task P10B-004: Agent G Forensic Path Write Guardrail.
Intercepts Agent G tool requests to strictly prevent file writes, appends,
deletions, or truncations against sealed forensic vault and database paths.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union

WRITE_ACTIONS: Set[str] = {
    "write",
    "write_file",
    "append",
    "append_file",
    "modify",
    "truncate",
    "delete",
    "delete_file",
    "unlink",
    "overwrite",
}

DEFAULT_PROTECTED_ROOTS: List[str] = [
    "vault/sealed",
    "forensics.db",
    "forensics.db-wal",
    "forensics.db-shm",
]


@dataclass(frozen=True)
class PathGuardDecision:
    allowed: bool
    target_path: str
    reason: Optional[str] = None


class AgentGForensicGuardrail:
    """Enforces write-blocking isolation on sealed evidence paths for Agent G."""

    def __init__(
        self,
        repo_root: Optional[Union[str, Path]] = None,
        protected_paths: Optional[List[str]] = None,
    ):
        self.repo_root = Path(repo_root or ".").resolve()
        paths_to_protect = protected_paths or DEFAULT_PROTECTED_ROOTS
        self.protected_paths = [
            (self.repo_root / p).resolve() for p in paths_to_protect
        ]

    def _is_path_protected(self, resolved_target: Path) -> bool:
        """Checks if a resolved path matches or resides within any protected root."""
        for prot in self.protected_paths:
            if resolved_target == prot:
                return True
            try:
                # Returns True if resolved_target is inside prot directory
                resolved_target.relative_to(prot)
                return True
            except ValueError:
                continue
        return False

    def evaluate_request(
        self,
        principal: str,
        action: str,
        target_path: Union[str, Path],
    ) -> PathGuardDecision:
        """Evaluates whether an action on a target path is permissible for principal."""
        # Resolve target canonical path safely
        raw_path = Path(target_path)
        if raw_path.is_absolute():
            resolved = raw_path.resolve()
        else:
            resolved = (self.repo_root / raw_path).resolve()

        # If operation is write-related and target is sealed path, enforce guard
        if action.lower() in WRITE_ACTIONS:
            if self._is_path_protected(resolved):
                return PathGuardDecision(
                    allowed=False,
                    target_path=str(resolved),
                    reason=f"Agent '{principal}' is strictly forbidden from writing to sealed evidence path: {resolved}",
                )

        return PathGuardDecision(
            allowed=True,
            target_path=str(resolved),
        )

    def enforce_guard(
        self,
        principal: str,
        action: str,
        target_path: Union[str, Path],
    ) -> None:
        """Enforces guard decision; raises PermissionError on violation."""
        decision = self.evaluate_request(principal, action, target_path)
        if not decision.allowed:
            raise PermissionError(decision.reason)
