"""
Task P11-008: Consensus Finding AVS Routing Module.
Enforces that HIGH and CRITICAL consensus findings (requires_avs=True)
obtain valid supermajority BLS QuorumCertificates before being routed
to Phase 9 mitigation gates or the egress gatekeeper.
"""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
import hashlib
from typing import Any, Dict, List, Optional, Set

from src.consensus.bls_aggregation import BLSAggregator, QuorumCertificate
from src.consensus.graph_enricher import ConsensusFinding


class RoutingVerdict(str, Enum):
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXEMPT = "EXEMPT"


@dataclass(frozen=True)
class ActionableMitigationPayload:
    finding_id: str
    finding_type: str
    severity: str
    crypto_digest: str
    routing_verdict: RoutingVerdict
    quorum_certificate: Optional[Dict[str, Any]]
    routed_at: float

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["routing_verdict"] = self.routing_verdict.value
        return data


class ConsensusAvsRouter:
    """Routes consensus findings through AVS consensus verification before mitigation."""

    def __init__(
        self,
        bls_aggregator: Optional[BLSAggregator] = None,
        registered_validators: Optional[List[str]] = None,
    ):
        if bls_aggregator is not None:
            self.bls_aggregator = bls_aggregator
        else:
            vals = registered_validators or ["val-1", "val-2", "val-3", "val-4"]
            self.bls_aggregator = BLSAggregator(registered_validators=vals)

        self._processed_attestations: Set[str] = set()

    @staticmethod
    def derive_consensus_receipt_hash(finding_digest: str) -> str:
        """Derives canonical consensus receipt hash bound to finding digest."""
        payload = f"consensus-receipt:{finding_digest}".encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def route_finding(
        self,
        finding: ConsensusFinding,
        quorum_certificate: Optional[QuorumCertificate] = None,
        receipt_hash: Optional[str] = None,
    ) -> ActionableMitigationPayload:
        """
        Evaluates finding requirements and routes to mitigation if verified or exempt.
        Raises PermissionError or ValueError on validation/authorization failure.
        """
        now = datetime.now(timezone.utc).timestamp()

        # Case 1: Low/Medium finding that does not require AVS consensus
        if not finding.requires_avs:
            return ActionableMitigationPayload(
                finding_id=finding.finding_id,
                finding_type=finding.finding_type,
                severity=finding.severity,
                crypto_digest=finding.crypto_digest,
                routing_verdict=RoutingVerdict.EXEMPT,
                quorum_certificate=None,
                routed_at=now,
            )

        # Case 2: High/Critical finding requires AVS consensus
        if quorum_certificate is None:
            raise PermissionError(
                f"Finding '{finding.finding_id}' of severity '{finding.severity}' "
                "requires AVS quorum certification, but no certificate was provided."
            )

        # 1. Digest binding verification
        if quorum_certificate.finding_digest != finding.crypto_digest:
            raise ValueError(
                f"Certificate digest mismatch: cert has '{quorum_certificate.finding_digest}', "
                f"expected finding digest '{finding.crypto_digest}'."
            )

        # 2. Replay protection
        if quorum_certificate.attestation_id in self._processed_attestations:
            raise ValueError(
                f"Replay attack detected: attestation '{quorum_certificate.attestation_id}' "
                "has already been routed."
            )

        # 3. Cryptographic aggregate verification
        effective_receipt_hash = receipt_hash or self.derive_consensus_receipt_hash(finding.crypto_digest)
        if not self.bls_aggregator.verify_quorum_certificate(quorum_certificate, effective_receipt_hash):
            raise PermissionError(
                f"AVS verification failed: QuorumCertificate for finding '{finding.finding_id}' "
                "has an invalid aggregate signature or fails supermajority threshold."
            )

        self._processed_attestations.add(quorum_certificate.attestation_id)

        return ActionableMitigationPayload(
            finding_id=finding.finding_id,
            finding_type=finding.finding_type,
            severity=finding.severity,
            crypto_digest=finding.crypto_digest,
            routing_verdict=RoutingVerdict.APPROVED,
            quorum_certificate=quorum_certificate.to_dict(),
            routed_at=now,
        )
