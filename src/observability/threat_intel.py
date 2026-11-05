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
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[2] / "scripts" / "lib"))
    from scanner_result import write_result  # noqa: E402

    intel = LiveThreatIntelEngine()

    # IP reputation (AbuseIPDB): DEMONSTRATION canary. 118.25.6.39 is
    # AbuseIPDB's own documented example query target (used verbatim in their
    # API docs' sample requests) -- this is NOT a claim that the address is
    # malicious. It proves the real AbuseIPDB integration end-to-end and
    # reports exactly whatever abuse score the live API returns today.
    DEMO_IP = "118.25.6.39"
    ip_result = intel.check_ip_reputation(DEMO_IP)
    print(f"[+] AbuseIPDB check {DEMO_IP} (DEMONSTRATION canary -- AbuseIPDB's "
          f"own documented example IP, not a claim of malice): "
          f"status={ip_result['status']} flagged={ip_result.get('flagged')} | "
          f"{ip_result.get('abuse_score', ip_result.get('detail'))}")

    # Smart-contract address screening: DEMONSTRATION canary against the real
    # OFAC SDN snapshot. Same address the real run-ofac-screening.py step
    # screens for real elsewhere in the pipeline -- this call only exercises
    # LiveThreatIntelEngine's second capability; it is not an independent
    # compliance signal.
    demo_addr = "0x098B716B8Aaf21512996dC57EB0615e2383E2f96"
    addr_result = intel.check_smart_contract_threat(demo_addr)
    print(f"[+] OFAC screen {demo_addr[:12]}...: status={addr_result['status']} "
          f"flagged={addr_result['flagged']} | "
          f"{addr_result.get('attribution') or addr_result.get('detail')}")

    if ip_result["status"] == "ok":
        overall = "ok"
    elif ip_result["status"] == "not_run":
        overall = "not_run"
    else:
        overall = "error"

    write_result(
        "osint", "threat_intel.py", overall,
        counts={"ip_checked": 0 if ip_result["status"] == "not_run" else 1,
                "ip_flagged": int(bool(ip_result.get("flagged"))),
                "address_checked": 1,
                "address_flagged": int(bool(addr_result.get("flagged")))},
        detail=(f"AbuseIPDB DEMONSTRATION canary ({DEMO_IP}, AbuseIPDB's own "
                f"documented example query target -- not a claim this address "
                f"is malicious): status={ip_result['status']}, "
                f"flagged={ip_result.get('flagged')}"
                + (f", abuse_score={ip_result.get('abuse_score')}"
                   if ip_result["status"] == "ok"
                   else f" ({ip_result.get('detail')})")),
        extra={"ip_reputation": ip_result, "smart_contract_threat": addr_result,
               "mode": "demonstration-canary"},
    )
