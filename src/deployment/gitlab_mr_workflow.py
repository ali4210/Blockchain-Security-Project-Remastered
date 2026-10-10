"""
Task P07-005: Draft GitLab Merge Request Workflow Generator.
Synthesizes structured, draft-locked GitLab Merge Request payloads for swarm patches,
binding finding references, QuorumCertificates, cryptographic patch digests, and tracking labels.
"""

from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.consensus.bls_aggregation import QuorumCertificate
from src.deployment.patch_sandbox import PatchManifest


@dataclass(frozen=True)
class GitLabMRPayload:
    title: str
    description: str
    source_branch: str
    target_branch: str
    labels: List[str]
    draft: bool
    finding_id: str
    attestation_id: str
    patch_digest: str
    created_at: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class GitLabMRWorkflow:
    """
    Constructs compliant draft GitLab Merge Requests enforcing human-in-the-loop gates.
    """

    DEFAULT_LABELS = [
        "security::finding",
        "remediation::swarm",
        "status::draft-review",
        "zone::deployment",
    ]

    def __init__(self, target_branch: str = "main"):
        self.target_branch = target_branch

    def generate_description(
        self,
        finding_id: str,
        target_contract: str,
        severity: str,
        patch_manifest: PatchManifest,
        certificate: QuorumCertificate,
    ) -> str:
        """Constructs an auditable markdown description for the Merge Request."""
        return (
            f"## Security Remediation: {finding_id}\n\n"
            f"- **Target Contract:** `{target_contract}`\n"
            f"- **Severity:** **{severity}**\n"
            f"- **Consensus Attestation ID:** `{certificate.attestation_id}`\n"
            f"- **Validator Quorum:** `{certificate.threshold_fraction}` validators confirmed\n\n"
            f"### Cryptographic Provenance\n"
            f"| Metric | SHA-256 Digest |\n"
            f"|---|---|\n"
            f"| Original Bytecode/Source | `{patch_manifest.originalDigest}` |\n"
            f"| Remediated Bytecode/Source | `{patch_manifest.patchedDigest}` |\n"
            f"| Unified Patch Digest | `{patch_manifest.patchDigest}` |\n\n"
            f"### Unified Diff Summary\n"
            f"```diff\n{patch_manifest.unifiedDiff.strip()}\n```\n\n"
            f"### Pre-Merge Verification Checklist (Human Review Gate)\n"
            f"- [ ] Verify that contract state mapping layout remains intact\n"
            f"- [ ] Verify regression tests pass on local Anvil testnet\n"
            f"- [ ] Verify QuorumCertificate aggregate signature matches registered keyring\n"
            f"- [ ] Security Lead / SOC attestation approval signed\n"
        )

    def create_draft_mr(
        self,
        finding_id: str,
        target_contract: str,
        severity: str,
        patch_manifest: PatchManifest,
        certificate: QuorumCertificate,
        custom_labels: Optional[List[str]] = None,
    ) -> GitLabMRPayload:
        """
        Creates a draft MR payload binding findings and QuorumCertificates.
        Enforces 'Draft: ' prefix and draft=True flag.
        """
        if not patch_manifest.patchDigest or len(patch_manifest.patchDigest) != 64:
            raise ValueError("Invalid patch manifest: missing or corrupt SHA-256 patch digest.")

        if not certificate.attestation_id:
            raise ValueError("Invalid QuorumCertificate: missing attestation ID.")

        title = f"Draft: [Remediation] {target_contract} - Fix {finding_id}"
        source_branch = f"remediation/{finding_id.lower()}-{patch_manifest.patchDigest[:8]}"
        labels = sorted(list(set(self.DEFAULT_LABELS + (custom_labels or []))))
        ts = datetime.now(timezone.utc).isoformat()

        description = self.generate_description(
            finding_id=finding_id,
            target_contract=target_contract,
            severity=severity,
            patch_manifest=patch_manifest,
            certificate=certificate,
        )

        return GitLabMRPayload(
            title=title,
            description=description,
            source_branch=source_branch,
            target_branch=self.target_branch,
            labels=labels,
            draft=True,
            finding_id=finding_id,
            attestation_id=certificate.attestation_id,
            patch_digest=patch_manifest.patchDigest,
            created_at=ts,
        )

    def export_mr_payload(self, mr_payload: GitLabMRPayload, output_path: Path) -> None:
        """Exports the MR payload to a clean JSON artifact for CI / API ingestion."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8") as f:
            json.dump(mr_payload.to_dict(), f, indent=2)
