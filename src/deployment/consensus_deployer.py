"""
Task P07-001 & P07-002: Consensus-Gated Deployment Engine with Vault Integration.
Enforces that smart contract deployments require cryptographic QuorumCertificates
and secure runtime deployment keys from VaultSecretStore.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.consensus.bls_aggregation import QuorumCertificate, BLSAggregator, ValidatorKeyring
from src.deployment.vault_secret_store import VaultSecretStore, VaultSecret


class DeploymentStatus(str, Enum):
    PENDING = "PENDING"
    DEPLOYED = "DEPLOYED"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"


@dataclass(frozen=True)
class DeploymentPlan:
    plan_id: str
    target_contract: str
    target_network: str
    bytecode_hash: str
    constructor_args: List[Any] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def compute_plan_digest(self) -> str:
        payload = {
            "plan_id": self.plan_id,
            "target_contract": self.target_contract,
            "target_network": self.target_network,
            "bytecode_hash": self.bytecode_hash,
            "constructor_args": self.constructor_args,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class DeploymentReceipt:
    deployment_id: str
    plan_id: str
    contract_address: str
    tx_hash: str
    deployer_address: str
    certificate_attestation_id: str
    status: DeploymentStatus
    deployed_at: str
    plan_digest: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ConsensusDeployer:
    """
    Coordinates consensus-confirmed deployment paths.
    Enforces QuorumCertificate attestation and pulls deployment credentials securely
    from VaultSecretStore with automated lease zeroization.
    """

    def __init__(
        self,
        aggregator: Optional[BLSAggregator] = None,
        keyring: Optional[ValidatorKeyring] = None,
        secret_store: Optional[VaultSecretStore] = None,
        rpc_url: str = "http://127.0.0.1:8545",
    ):
        self.keyring = keyring or ValidatorKeyring()
        self.aggregator = aggregator or BLSAggregator(["validator-1", "validator-2", "validator-3"], keyring=self.keyring)
        self.secret_store = secret_store or VaultSecretStore()
        self.rpc_url = rpc_url
        self._deployed_contracts: Dict[str, DeploymentReceipt] = {}

    def deploy(
        self,
        plan: DeploymentPlan,
        certificate: Optional[QuorumCertificate],
        receipt_hash: str,
        role: str = "admin",
    ) -> DeploymentReceipt:
        """
        Executes deployment if and only if the plan is authorized by a verified QuorumCertificate.
        Resolves deployer key from VaultSecretStore and ensures lease zeroization.
        """
        if not certificate:
            raise PermissionError(
                f"Deployment BLOCKED: Plan '{plan.plan_id}' lacks a required QuorumCertificate."
            )

        # Cryptographic verification of QuorumCertificate
        is_cert_valid = self.aggregator.verify_quorum_certificate(certificate, receipt_hash)
        if not is_cert_valid:
            raise PermissionError(
                f"Deployment BLOCKED: QuorumCertificate for plan '{plan.plan_id}' is cryptographically invalid or tampered."
            )

        # Binding check: Certificate finding_digest MUST match the plan bytecode_hash
        if certificate.finding_digest != plan.bytecode_hash:
            raise ValueError(
                f"Deployment BLOCKED: Bytecode digest mismatch! "
                f"Plan bytecode_hash '{plan.bytecode_hash}' != Certificate finding_digest '{certificate.finding_digest}'."
            )

        # Retrieve ephemeral deployment credential from Vault
        secret: Optional[VaultSecret] = None
        try:
            secret = self.secret_store.get_deployer_key(plan.target_network, role=role)
            raw_key = secret.get_raw_value()
            deployer_address = "0x" + hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:40]
        finally:
            if secret:
                self.secret_store.revoke_lease(secret.lease_id)

        # Deterministic simulation of deployment transaction and contract address
        plan_digest = plan.compute_plan_digest()
        deploy_salt = f"{plan_digest}:{certificate.aggregate_signature[:16]}:{deployer_address}"
        contract_addr = "0x" + hashlib.sha256(f"contract:{deploy_salt}".encode("utf-8")).hexdigest()[:40]
        tx_hash = "0x" + hashlib.sha256(f"tx:{deploy_salt}".encode("utf-8")).hexdigest()
        deployment_id = f"DEP-{plan.target_contract}-{plan_digest[:8]}"

        receipt = DeploymentReceipt(
            deployment_id=deployment_id,
            plan_id=plan.plan_id,
            contract_address=contract_addr,
            tx_hash=tx_hash,
            deployer_address=deployer_address,
            certificate_attestation_id=certificate.attestation_id,
            status=DeploymentStatus.DEPLOYED,
            deployed_at=datetime.now(timezone.utc).isoformat(),
            plan_digest=plan_digest,
        )

        self._deployed_contracts[deployment_id] = receipt
        return receipt

    def get_receipt(self, deployment_id: str) -> Optional[DeploymentReceipt]:
        return self._deployed_contracts.get(deployment_id)
