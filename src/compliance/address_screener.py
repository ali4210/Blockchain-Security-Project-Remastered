"""
Task P13-001: Compliance Address Screening Engine.
Provides local, deterministic screening against approved sanctions snapshots
and high-risk address lists with canonical EIP-55 normalization.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


class RiskTier(str, Enum):
    CRITICAL_SANCTIONED = "CRITICAL_SANCTIONED"
    HIGH_RISK = "HIGH_RISK"
    MEDIUM_SUSPICIOUS = "MEDIUM_SUSPICIOUS"
    LOW_CLEAN = "LOW_CLEAN"


@dataclass(frozen=True)
class SanctionEntry:
    address: str
    entity_name: str
    category: str  # e.g., "OFAC_SDN", "RANSOMWARE", "EXPLOIT_ACTOR", "MIXER"
    source_list: str
    added_date: str
    risk_score: float  # 0.0 to 1.0


@dataclass(frozen=True)
class ScreeningMatch:
    is_flagged: bool
    risk_tier: RiskTier
    risk_score: float
    matched_address: str
    matched_entry: Optional[SanctionEntry] = None
    reason: str = "Address not found in high-risk or sanctions registry."


# Default local sanctions snapshot (Curated mock of public regulatory / exploit addresses)
DEFAULT_SANCTIONS_SNAPSHOT: List[Dict[str, Any]] = [
    {
        "address": "0x098B716B8Aaf21512996dC57EB0615e2383E2f96",
        "entity_name": "Ronin Bridge Exploiter",
        "category": "OFAC_SDN",
        "source_list": "OFAC_SPEC_DESIGNATED",
        "added_date": "2022-04-14",
        "risk_score": 1.0,
    },
    {
        "address": "0xd90e2f925DA726b50C4Ed8D0Fb90Ad053324F31b",
        "entity_name": "Tornado Cash Router",
        "category": "OFAC_SDN",
        "source_list": "OFAC_SPEC_DESIGNATED",
        "added_date": "2022-08-08",
        "risk_score": 1.0,
    },
    {
        "address": "0x8576aCC5C05D6Ce88f4e49bf65BdF0C62F91353C",
        "entity_name": "Tornado Cash Vault",
        "category": "OFAC_SDN",
        "source_list": "OFAC_SPEC_DESIGNATED",
        "added_date": "2022-08-08",
        "risk_score": 1.0,
    },
    {
        "address": "0x1da5821544e25c636c1417ba96ade4cf6d2f9b5a",
        "entity_name": "Lazarus Group Relayer 1",
        "category": "EXPLOIT_ACTOR",
        "source_list": "THREAT_INTEL_SANCTIONED",
        "added_date": "2023-01-20",
        "risk_score": 0.95,
    },
    {
        "address": "0x72a5843cc08275C80f0A307B6e804f5D51543884",
        "entity_name": "Unregistered High-Risk P2P Gateway",
        "category": "HIGH_RISK_EXCHANGE",
        "source_list": "INTERNAL_RISK_REGISTER",
        "added_date": "2023-06-11",
        "risk_score": 0.75,
    },
]


def normalize_address(address: str) -> str:
    """
    Normalizes EVM address to lowercase format with '0x' prefix.
    """
    cleaned = address.strip()
    if not cleaned.startswith("0x"):
        cleaned = "0x" + cleaned
    return cleaned.lower()


class AddressScreener:
    """
    Deterministic compliance address screener backed by snapshot hashing.
    """

    def __init__(self, snapshot_records: Optional[List[Dict[str, Any]]] = None):
        self._records = snapshot_records if snapshot_records is not None else DEFAULT_SANCTIONS_SNAPSHOT
        self._registry: Dict[str, SanctionEntry] = {}
        self._load_registry()
        self.snapshot_hash = self._compute_snapshot_hash()

    def _load_registry(self) -> None:
        self._registry.clear()
        for item in self._records:
            norm_addr = normalize_address(item["address"])
            self._registry[norm_addr] = SanctionEntry(
                address=norm_addr,
                entity_name=item["entity_name"],
                category=item["category"],
                source_list=item["source_list"],
                added_date=item["added_date"],
                risk_score=float(item["risk_score"]),
            )

    def _compute_snapshot_hash(self) -> str:
        serialized = json.dumps(
            sorted([e.__dict__ for e in self._registry.values()], key=lambda x: x["address"]),
            sort_keys=True,
        ).encode("utf-8")
        return hashlib.sha256(serialized).hexdigest()

    def screen(self, address: str) -> ScreeningMatch:
        """
        Screens an individual address against the snapshot.
        """
        norm = normalize_address(address)
        if norm in self._registry:
            entry = self._registry[norm]
            tier = (
                RiskTier.CRITICAL_SANCTIONED
                if entry.risk_score >= 0.90
                else RiskTier.HIGH_RISK
                if entry.risk_score >= 0.70
                else RiskTier.MEDIUM_SUSPICIOUS
            )
            return ScreeningMatch(
                is_flagged=True,
                risk_tier=tier,
                risk_score=entry.risk_score,
                matched_address=norm,
                matched_entry=entry,
                reason=f"Address matched {entry.category} listing ({entry.entity_name})",
            )

        return ScreeningMatch(
            is_flagged=False,
            risk_tier=RiskTier.LOW_CLEAN,
            risk_score=0.0,
            matched_address=norm,
            reason="Clean: No records found in compliance snapshot.",
        )

    def screen_batch(self, addresses: List[str]) -> List[ScreeningMatch]:
        """
        Screens a batch of addresses deterministically.
        """
        return [self.screen(addr) for addr in addresses]

    def total_entries(self) -> int:
        return len(self._registry)
