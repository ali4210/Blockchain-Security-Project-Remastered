#!/usr/bin/env python3
"""Zone: OFAC sanctioned-address screening gate.

Screens one or more addresses against the REAL OFAC SDN crypto snapshot
(scripts/mirror-ofac.py builds it; src/compliance/address_screener.py matches).

Addresses screened:
  * TARGET_SCREEN_ADDRESS env (comma-separated) if set — the real addresses the
    operator wants checked (e.g. a deployer / relayer / counterparty).
  * otherwise a DEMONSTRATION canary pair: one documented, verified OFAC-listed
    address (must flag) and one clean control (must not). This local fixture
    pipeline has no real external counterparty, so the default is explicitly a
    capability demonstration, not a live screen.

Honest status via scanner_result:
  * not_run  — snapshot missing or stale (never a guessed clean result)
  * error    — screening raised unexpectedly
  * ok       — screening really ran against a present, current snapshot
"""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
from scanner_result import ROOT, write_result  # noqa: E402
from src.compliance.address_screener import AddressScreener, SnapshotUnavailable  # noqa: E402

# Documented demonstration canary (verified present in the real OFAC SDN list as
# of this writing: Lazarus Group / Ronin bridge), plus a clean control.
CANARY_SANCTIONED = "0x098B716B8Aaf21512996dC57EB0615e2383E2f96"
CANARY_CLEAN = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"


def targets():
    env = os.getenv("TARGET_SCREEN_ADDRESS", "").strip()
    if env:
        return [a.strip() for a in env.split(",") if a.strip()], False
    return [CANARY_SANCTIONED, CANARY_CLEAN], True


def main():
    print("[+] [COMPLIANCE] OFAC SDN sanctioned-address screening...")
    try:
        screener = AddressScreener()
    except SnapshotUnavailable as exc:
        return write_result("ofac-screening", "ofac-sdn", "not_run", detail=str(exc)[:200])

    addrs, is_demo = targets()
    try:
        results = []
        for addr in addrs:
            m = screener.screen(addr)
            results.append({
                "address": addr,
                "flagged": m.is_flagged,
                "risk_tier": m.risk_tier.value,
                "reason": m.reason,
                "entity": m.matched_entry.entity_name if m.matched_entry else None,
            })
            mark = "FLAGGED" if m.is_flagged else "clean"
            print(f"    -> {addr}: {mark} ({m.reason})")
    except Exception as exc:  # noqa: BLE001
        return write_result("ofac-screening", "ofac-sdn", "error", detail=str(exc)[:200])

    flagged = sum(1 for r in results if r["flagged"])
    meta = screener.snapshot_meta
    report = {
        "mode": "demonstration-canary" if is_demo else "operator-supplied",
        "snapshot": {k: meta.get(k) for k in ("source_url", "downloaded_at", "sdn_csv_sha256", "address_count")},
        "screened": results,
    }
    report_file = ROOT / "reports" / "ofac-screening-report.json"
    report_file.parent.mkdir(parents=True, exist_ok=True)
    report_file.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    note = (" (DEMONSTRATION canary: no real counterparty in this fixture pipeline)"
            if is_demo else "")
    detail = (f"screened {len(results)} address(es), {flagged} flagged against OFAC SDN "
              f"snapshot {meta.get('downloaded_at')} ({meta.get('address_count')} addrs){note}")
    return write_result("ofac-screening", "ofac-sdn", "ok",
                        counts={"screened": len(results), "flagged": flagged,
                                "clean": len(results) - flagged},
                        raw_report=report_file, detail=detail,
                        extra={"mode": report["mode"]})


if __name__ == "__main__":
    main()
