"""Compliance address screening against a REAL OFAC SDN snapshot.

The matching engine (normalization, exact lookup, risk tiers) is backed by a
dated, hashed local snapshot of the official OFAC Specially Designated Nationals
cryptocurrency addresses, produced out of band by scripts/mirror-ofac.py (same
offline-mirror pattern as the NVD/OSV work).

HONEST BEHAVIOUR:
  * No snapshot, or a stale one -> SnapshotUnavailable is raised. Callers must
    translate that into a not_run result. A screen is NEVER silently returned
    as "clean" when the data source is missing.
  * A clean verdict (LOW_CLEAN) means the address was really checked against a
    present, current snapshot and not found. It is a real result, not a failure
    dressed up as clean.
  * Tests inject their own records via snapshot_records= so they never depend on
    the live, changing OFAC list.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

DEFAULT_SNAPSHOT_PATH = Path.home() / ".local/state/ofac-mirror/ofac-crypto-snapshot.json"
DEFAULT_MAX_AGE_DAYS = 30

_ETH_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


class SnapshotUnavailable(RuntimeError):
    """The OFAC snapshot is missing or too old to be trusted. Screening must
    report not_run rather than guess a clean result."""


class RiskTier(str, Enum):
    CRITICAL_SANCTIONED = "CRITICAL_SANCTIONED"
    HIGH_RISK = "HIGH_RISK"
    MEDIUM_SUSPICIOUS = "MEDIUM_SUSPICIOUS"
    LOW_CLEAN = "LOW_CLEAN"


@dataclass(frozen=True)
class SanctionEntry:
    address: str
    entity_name: str
    category: str          # e.g. "OFAC_SDN"
    source_list: str
    added_date: str
    risk_score: float      # 0.0-1.0 (OFAC SDN listing == 1.0)
    currency: str = ""


@dataclass(frozen=True)
class ScreeningMatch:
    is_flagged: bool
    risk_tier: RiskTier
    risk_score: float
    matched_address: str
    matched_entry: Optional[SanctionEntry] = None
    reason: str = "Address not found in high-risk or sanctions registry."


def normalize_address(address: str) -> str:
    """Canonicalize for matching. ETH-style hex is lowercased (case-insensitive);
    everything else (e.g. Bitcoin, which IS case-sensitive) is left verbatim so
    we never corrupt a non-EVM address."""
    cleaned = (address or "").strip()
    bare = cleaned[2:] if cleaned.lower().startswith("0x") else cleaned
    if re.fullmatch(r"[0-9a-fA-F]{40}", bare):
        return "0x" + bare.lower()
    return cleaned


class AddressScreener:
    """Deterministic screener backed by the OFAC crypto snapshot.

    snapshot_records: inject records directly (tests); each needs at least
      'address' and 'entity_name', optional 'currency'/'category'/'risk_score'.
    snapshot_path / max_age_days: where to load the real snapshot and how old it
      may be before it is refused.
    """

    def __init__(self, snapshot_records: Optional[List[Dict[str, Any]]] = None,
                 snapshot_path: Optional[Path] = None,
                 max_age_days: int = DEFAULT_MAX_AGE_DAYS):
        if snapshot_records is not None:
            self._records = snapshot_records
            self.snapshot_meta: Dict[str, Any] = {"source": "injected",
                                                   "address_count": len(snapshot_records)}
        else:
            self._records, self.snapshot_meta = self._load_snapshot(
                Path(snapshot_path) if snapshot_path else DEFAULT_SNAPSHOT_PATH, max_age_days)
        self._registry: Dict[str, SanctionEntry] = {}
        self._load_registry()
        self.snapshot_hash = self._compute_snapshot_hash()

    @staticmethod
    def _load_snapshot(path: Path, max_age_days: int):
        if not path.is_file():
            raise SnapshotUnavailable(
                f"OFAC snapshot not found at {path}; run scripts/mirror-ofac.py to build it")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, OSError) as exc:
            raise SnapshotUnavailable(f"OFAC snapshot at {path} is unreadable: {exc}")
        downloaded_at = data.get("downloaded_at")
        if downloaded_at:
            try:
                age = datetime.now(timezone.utc) - datetime.fromisoformat(downloaded_at)
                if age.days > max_age_days:
                    raise SnapshotUnavailable(
                        f"OFAC snapshot is stale ({age.days}d old > {max_age_days}d limit); "
                        f"re-run scripts/mirror-ofac.py")
            except ValueError:
                raise SnapshotUnavailable(f"OFAC snapshot has an invalid downloaded_at: {downloaded_at!r}")
        entries = data.get("entries")
        if not entries:
            raise SnapshotUnavailable(f"OFAC snapshot at {path} contains no entries")
        meta = {k: data.get(k) for k in
                ("source_url", "downloaded_at", "sdn_csv_sha256", "address_count", "by_currency")}
        return entries, meta

    def _load_registry(self) -> None:
        self._registry.clear()
        for item in self._records:
            norm = normalize_address(item["address"])
            self._registry[norm] = SanctionEntry(
                address=norm,
                entity_name=item.get("entity_name", "UNKNOWN"),
                category=item.get("category", "OFAC_SDN"),
                source_list=item.get("source_list", "OFAC_SDN"),
                added_date=item.get("added_date", self.snapshot_meta.get("downloaded_at", "")),
                risk_score=float(item.get("risk_score", 1.0)),
                currency=item.get("currency", ""),
            )

    def _compute_snapshot_hash(self) -> str:
        serialized = json.dumps(
            sorted([e.address for e in self._registry.values()]), sort_keys=True).encode("utf-8")
        return hashlib.sha256(serialized).hexdigest()

    def screen(self, address: str) -> ScreeningMatch:
        norm = normalize_address(address)
        entry = self._registry.get(norm)
        if entry:
            tier = (RiskTier.CRITICAL_SANCTIONED if entry.risk_score >= 0.90
                    else RiskTier.HIGH_RISK if entry.risk_score >= 0.70
                    else RiskTier.MEDIUM_SUSPICIOUS)
            cur = f" [{entry.currency}]" if entry.currency else ""
            return ScreeningMatch(
                is_flagged=True, risk_tier=tier, risk_score=entry.risk_score,
                matched_address=norm, matched_entry=entry,
                reason=f"Address on {entry.source_list}{cur}: {entry.entity_name}")
        return ScreeningMatch(
            is_flagged=False, risk_tier=RiskTier.LOW_CLEAN, risk_score=0.0,
            matched_address=norm,
            reason="Clean: not found in the OFAC SDN snapshot.")

    def screen_batch(self, addresses: List[str]) -> List[ScreeningMatch]:
        return [self.screen(a) for a in addresses]

    def total_entries(self) -> int:
        return len(self._registry)
