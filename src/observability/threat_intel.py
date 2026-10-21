"""OSINT / threat-intel checks with honest failure semantics.

Address screening delegates to the REAL OFAC SDN snapshot via AddressScreener
(src/compliance/address_screener.py). There is no second hardcoded sanctions
list here anymore, and the broken OTX "IPv4 indicator" call for Ethereum
addresses has been removed (OTX has no Ethereum-address indicator type, so that
call never worked; OFAC SDN is the authoritative source for sanctioned
addresses).

A lookup that cannot be performed (no snapshot, no API key) or that fails is
reported with an explicit status of 'not_run' or 'error' and flagged=None. It is
NEVER returned as a clean/"Verified Clean" result — only a lookup that actually
ran against present data may say flagged=False.
"""
import os
from typing import Any, Dict, Optional

import requests

from src.compliance.address_screener import AddressScreener, SnapshotUnavailable


class LiveThreatIntelEngine:
    """IP reputation (AbuseIPDB) + sanctioned-address screening (OFAC SDN)."""

    def __init__(self):
        self.abuseipdb_key = os.getenv("ABUSEIPDB_API_KEY", "")
        self._screener: Optional[AddressScreener] = None
        self._screener_error: Optional[str] = None
        try:
            self._screener = AddressScreener()
        except SnapshotUnavailable as exc:
            self._screener_error = str(exc)

    def check_ip_reputation(self, ip_address: str) -> Dict[str, Any]:
        """AbuseIPDB lookup. Without a key, or on failure, reports not_run/error
        with flagged=None rather than pretending the IP is clean."""
        if ip_address in ("127.0.0.1", "localhost"):
            return {"source": "AbuseIPDB", "ip": ip_address, "status": "not_run",
                    "flagged": None, "detail": "loopback address not screened"}
        if not self.abuseipdb_key:
            return {"source": "AbuseIPDB", "ip": ip_address, "status": "not_run",
                    "flagged": None, "detail": "ABUSEIPDB_API_KEY not set"}
        try:
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": self.abuseipdb_key, "Accept": "application/json"},
                params={"ipAddress": ip_address, "maxAgeInDays": 90}, timeout=5)
            if resp.status_code != 200:
                return {"source": "AbuseIPDB", "ip": ip_address, "status": "error",
                        "flagged": None, "detail": f"HTTP {resp.status_code}"}
            data = resp.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            return {"source": "AbuseIPDB", "ip": ip_address, "status": "ok",
                    "flagged": score > 20, "abuse_score": score,
                    "country": data.get("countryCode", "UNKNOWN")}
        except Exception as exc:  # noqa: BLE001
            return {"source": "AbuseIPDB", "ip": ip_address, "status": "error",
                    "flagged": None, "detail": str(exc)[:120]}

    def check_smart_contract_threat(self, address: str) -> Dict[str, Any]:
        """Screen an address against the real OFAC SDN snapshot. If the snapshot
        is unavailable, report not_run (never a fabricated clean result)."""
        if self._screener is None:
            return {"source": "OFAC SDN snapshot", "target": address, "status": "not_run",
                    "flagged": None, "detail": self._screener_error or "screener unavailable"}
        match = self._screener.screen(address)
        return {
            "source": "OFAC SDN snapshot",
            "target": address,
            "status": "ok",
            "flagged": match.is_flagged,
            "attribution": match.matched_entry.entity_name if match.matched_entry else None,
            "risk_tier": match.risk_tier.value,
            "detail": match.reason,
            "snapshot_sha256": self._screener.snapshot_meta.get("sdn_csv_sha256"),
        }


if __name__ == "__main__":
    intel = LiveThreatIntelEngine()
    # Demonstration against a documented, verified OFAC-listed address (Lazarus
    # Group / Ronin bridge). This is a capability demo, not a live counterparty.
    demo = "0x098B716B8Aaf21512996dC57EB0615e2383E2f96"
    res = intel.check_smart_contract_threat(demo)
    print(f"[+] OFAC screen {demo[:12]}...: status={res['status']} "
          f"flagged={res['flagged']} | {res.get('attribution') or res.get('detail')}")
