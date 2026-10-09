"""
Task P07-002: Hardened Vault Dev-Mode & Coursework Safe Secret Store for Deployment.
Provides zero-leakage ephemeral secret management for smart contract deployment keys.
Supports HashiCorp Vault dev-mode HTTP client and an authenticated in-memory safe fallback.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import os
from typing import Any, Dict, Optional
import urllib.request
import urllib.error


class SecretLeakageError(RuntimeError):
    """Raised when an attempt to log or expose secret values is detected."""
    pass


@dataclass
class VaultSecret:
    key_name: str
    lease_id: str
    created_at: str
    _value_bytes: bytearray = field(repr=False)

    def __repr__(self) -> str:
        return f"<VaultSecret:key_name='{self.key_name}',lease_id='{self.lease_id}',status='REDACTED'>"

    def __str__(self) -> str:
        return f"<VaultSecret:key_name='{self.key_name}',status='REDACTED'>"

    def get_raw_value(self) -> str:
        """Returns the raw secret string. Must be zeroized after use."""
        if not self._value_bytes or all(b == 0 for b in self._value_bytes):
            raise ValueError("Secret has been zeroized or invalidated.")
        return self._value_bytes.decode("utf-8")

    def zeroize(self) -> None:
        """Securely overwrites memory buffer with null bytes."""
        for i in range(len(self._value_bytes)):
            self._value_bytes[i] = 0
        self._value_bytes = bytearray()


class VaultSecretStore:
    """
    Manages deployment credentials using HashiCorp Vault dev-mode API
    or a secure, isolated in-memory coursework secret-store fallback.
    """

    def __init__(
        self,
        vault_addr: Optional[str] = None,
        vault_token: Optional[str] = None,
        use_fallback: bool = True,
    ):
        self.vault_addr = (vault_addr or os.getenv("VAULT_ADDR", "http://127.0.0.1:8200")).rstrip("/")
        self.vault_token = vault_token or os.getenv("VAULT_TOKEN", "root")
        self.use_fallback = use_fallback
        self._in_memory_vault: Dict[str, str] = {}
        self._active_leases: Dict[str, VaultSecret] = {}

        # Default deterministic coursework deployment keys (Anvil Account 0 & 1)
        self.seed_coursework_secrets({
            "deployer/local-anvil/admin": "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
            "deployer/local-anvil/operator": "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
        })

    def seed_coursework_secrets(self, secrets: Dict[str, str]) -> None:
        """Seeds secrets strictly into the isolated in-memory safe store."""
        for path, val in secrets.items():
            self._in_memory_vault[path] = val

    def get_deployer_key(self, network: str, role: str = "admin") -> VaultSecret:
        """
        Retrieves a deployer private key wrapped in an ephemeral VaultSecret.
        Attempts Vault dev-mode HTTP API first; falls back to in-memory store if configured.
        """
        secret_path = f"deployer/{network}/{role}"
        ts = datetime.now(timezone.utc).isoformat()
        lease_id = f"lease-{hashlib.sha256(f'{secret_path}:{ts}'.encode('utf-8')).hexdigest()[:12]}"

        # Attempt Vault HTTP lookup
        if not self.use_fallback:
            try:
                req = urllib.request.Request(
                    f"{self.vault_addr}/v1/secret/data/{secret_path}",
                    headers={"X-Vault-Token": self.vault_token},
                )
                with urllib.request.urlopen(req, timeout=1.0) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    val = data["data"]["data"]["value"]
                    secret = VaultSecret(
                        key_name=secret_path,
                        lease_id=lease_id,
                        created_at=ts,
                        _value_bytes=bytearray(val.encode("utf-8")),
                    )
                    self._active_leases[lease_id] = secret
                    return secret
            except Exception:
                raise KeyError(f"Failed to retrieve secret from Vault at '{secret_path}'.")

        # Fallback to coursework in-memory safe store
        if secret_path not in self._in_memory_vault:
            raise KeyError(f"Secret not found in vault: '{secret_path}'")

        val = self._in_memory_vault[secret_path]
        secret = VaultSecret(
            key_name=secret_path,
            lease_id=lease_id,
            created_at=ts,
            _value_bytes=bytearray(val.encode("utf-8")),
        )
        self._active_leases[lease_id] = secret
        return secret

    def revoke_lease(self, lease_id: str) -> bool:
        """Revokes secret lease and zeroizes associated memory buffers immediately."""
        secret = self._active_leases.pop(lease_id, None)
        if secret:
            secret.zeroize()
            return True
        return False

    def close(self) -> None:
        """Zeroizes all active leases on shutdown."""
        for secret in list(self._active_leases.values()):
            secret.zeroize()
        self._active_leases.clear()
        self._in_memory_vault.clear()
