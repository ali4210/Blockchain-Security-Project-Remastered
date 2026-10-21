#!/usr/bin/env python3
"""Build a dated, hashed local snapshot of OFAC SDN cryptocurrency addresses.

Same offline-mirror pattern as mirror-nvd.sh: this runs OUT OF BAND (not inside
the gated pipeline), fetches the official OFAC Specially Designated Nationals
list, extracts every "Digital Currency Address - <CUR> <addr>" entry, and writes
a snapshot the screener reads. The screener never fetches the network itself.

Source: OFAC sanctions list service (the public, machine-readable SDN.CSV). The
crypto addresses live in the Remarks field as "Digital Currency Address - ETH
0x...", "... - XBT 1...", etc. — this is the authoritative government source.

Usage:
    python3 scripts/mirror-ofac.py            # fetch + write snapshot
    python3 scripts/mirror-ofac.py --from-csv /path/sdn.csv   # parse a local copy

Writes ~/.local/state/ofac-mirror/{sdn.csv, ofac-crypto-snapshot.json}.
Exits non-zero (and leaves any existing snapshot untouched) on failure.
"""
import argparse
import csv
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

SDN_CSV_URL = "https://sanctionslistservice.ofac.treas.gov/api/download/sdn.csv"
MIRROR_DIR = Path.home() / ".local/state/ofac-mirror"
SNAPSHOT = MIRROR_DIR / "ofac-crypto-snapshot.json"
RAW_CSV = MIRROR_DIR / "sdn.csv"
SCHEMA_VERSION = 1

# "Digital Currency Address - ETH 0xabc...; " — currency token then the address,
# stopped at the first separator OFAC uses (; , " or whitespace).
ADDR_RE = re.compile(r"Digital Currency Address - ([A-Z0-9]+)\s+([^;,\"\s]+)")


def parse_csv(text):
    """Extract {address_lower: {address, currency, entity_name}} from SDN.CSV text."""
    entries = {}
    for row in csv.reader(text.splitlines()):
        if len(row) < 12:
            continue
        entity_name = row[1].strip().strip('"')
        remarks = row[-1]
        for currency, addr in ADDR_RE.findall(remarks):
            entries.setdefault(addr.lower(), {
                "address": addr,
                "currency": currency,
                "entity_name": entity_name,
            })
    return entries


def build_snapshot(csv_bytes, source):
    text = csv_bytes.decode("latin-1")
    entries = parse_csv(text)
    if not entries:
        raise RuntimeError("no digital-currency addresses parsed; refusing to write an empty snapshot")
    by_currency = {}
    for e in entries.values():
        by_currency[e["currency"]] = by_currency.get(e["currency"], 0) + 1
    return {
        "schemaVersion": SCHEMA_VERSION,
        "source": source,
        "source_url": SDN_CSV_URL,
        "downloaded_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sdn_csv_sha256": hashlib.sha256(csv_bytes).hexdigest(),
        "address_count": len(entries),
        "by_currency": dict(sorted(by_currency.items())),
        "entries": sorted(entries.values(), key=lambda e: e["address"].lower()),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--from-csv", help="parse a local SDN.CSV instead of fetching")
    args = ap.parse_args()

    if args.from_csv:
        csv_bytes = Path(args.from_csv).read_bytes()
        source = f"local:{args.from_csv}"
    else:
        import requests  # imported lazily so --from-csv works without the dep
        print(f"[*] [OFAC MIRROR] fetching {SDN_CSV_URL} ...")
        resp = requests.get(SDN_CSV_URL, timeout=120, allow_redirects=True)
        resp.raise_for_status()
        csv_bytes = resp.content
        source = SDN_CSV_URL

    snapshot = build_snapshot(csv_bytes, source)
    MIRROR_DIR.mkdir(parents=True, exist_ok=True)
    RAW_CSV.write_bytes(csv_bytes)
    SNAPSHOT.write_text(json.dumps(snapshot, indent=2) + "\n", encoding="utf-8")
    print(f"[+] [OFAC MIRROR] wrote {SNAPSHOT}")
    print(f"    addresses: {snapshot['address_count']}  by_currency: {snapshot['by_currency']}")
    print(f"    sdn.csv sha256: {snapshot['sdn_csv_sha256'][:16]}...  downloaded_at: {snapshot['downloaded_at']}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001 — surface the real reason, leave old snapshot intact
        print(f"[-] [OFAC MIRROR] failed: {exc}", file=sys.stderr)
        sys.exit(1)
