#!/usr/bin/env python3
"""Build a dated, hashed local snapshot of OpenSanctions' real Consolidated
Sanctions collection (name/entity-level KYC/AML screening data).

Same offline-mirror pattern as mirror-ofac.py/mirror-nvd.sh: this runs OUT OF
BAND (not inside the gated pipeline), fetches OpenSanctions' real, publicly
downloadable bulk CSV, and writes a snapshot src/compliance/kyc_verifier.py
reads. The screener never fetches the network itself.

REAL LICENSE, VERIFIED (not assumed): the OpenSanctions dataset is licensed
under Creative Commons Attribution-NonCommercial 4.0 (CC BY-NC 4.0) --
https://www.opensanctions.org/licensing/. Free bulk download, no API key,
for non-commercial use (this project's own real context: EduQual L6
coursework). Any commercial use of this data would need OpenSanctions' own
paid Screening/Reseller license -- this mirror and kyc_verifier.py are built
on that basis and must not be repurposed commercially without one. The
yente query-engine SOFTWARE OpenSanctions itself runs is separately open
source, but this project only consumes the published bulk data file
directly (no yente/ElasticSearch deployment), which needs no extra license
of its own beyond the data license above.

Source: the "sanctions" (Consolidated Sanctions) collection specifically --
308,917 entities, government sanctions lists only -- not the much larger
"default" collection (3.9M entities including PEPs/crime/everything),
which is disproportionate to this project's real v1 scope. Dataset index:
https://data.opensanctions.org/datasets/latest/sanctions/index.json

Usage:
    python3 scripts/mirror-opensanctions.py                  # fetch + write snapshot
    python3 scripts/mirror-opensanctions.py --from-csv /path/targets.simple.csv

Writes ~/.local/state/opensanctions-mirror/{targets.simple.csv, opensanctions-sanctions-snapshot.json}.
Exits non-zero (and leaves any existing snapshot untouched) on failure.
"""
import argparse
import csv
import hashlib
import io
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

INDEX_URL = "https://data.opensanctions.org/datasets/latest/sanctions/index.json"
MIRROR_DIR = Path.home() / ".local/state/opensanctions-mirror"
SNAPSHOT = MIRROR_DIR / "opensanctions-sanctions-snapshot.json"
RAW_CSV = MIRROR_DIR / "targets.simple.csv"
SCHEMA_VERSION = 1
LICENSE = "CC BY-NC 4.0 (non-commercial) -- https://www.opensanctions.org/licensing/"


def parse_csv(text):
    """Extract real entities from targets.simple.csv's real columns:
    id,schema,name,aliases,birth_date,countries,addresses,identifiers,
    sanctions,phones,emails,program_ids,dataset,first_seen,last_seen,last_change."""
    entries = []
    reader = csv.DictReader(io.StringIO(text))
    for row in reader:
        name = (row.get("name") or "").strip()
        if not name:
            continue
        entries.append({
            "id": row.get("id", ""),
            "schema": row.get("schema", ""),
            "name": name,
            "aliases": [a for a in (row.get("aliases") or "").split(";") if a.strip()],
            "countries": [c for c in (row.get("countries") or "").split(";") if c.strip()],
            "sanctions": (row.get("sanctions") or "")[:300],
            "program_ids": [p for p in (row.get("program_ids") or "").split(";") if p.strip()],
            "dataset": (row.get("dataset") or ""),
        })
    return entries


def build_snapshot(csv_bytes, source, index_meta=None):
    text = csv_bytes.decode("utf-8", errors="replace")
    entries = parse_csv(text)
    if not entries:
        raise RuntimeError("no entities parsed; refusing to write an empty snapshot")
    return {
        "schemaVersion": SCHEMA_VERSION,
        "license": LICENSE,
        "source": source,
        "source_dataset": "sanctions",
        "downloaded_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "csv_sha256": hashlib.sha256(csv_bytes).hexdigest(),
        "entity_count": len(entries),
        "upstream_version": (index_meta or {}).get("version"),
        "entries": entries,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--from-csv", help="parse a local targets.simple.csv instead of fetching")
    args = ap.parse_args()

    index_meta = None
    if args.from_csv:
        csv_bytes = Path(args.from_csv).read_bytes()
        source = f"local:{args.from_csv}"
    else:
        import requests  # imported lazily so --from-csv works without the dep
        print(f"[*] [OPENSANCTIONS MIRROR] fetching dataset index {INDEX_URL} ...")
        idx_resp = requests.get(INDEX_URL, timeout=30)
        idx_resp.raise_for_status()
        index_meta = idx_resp.json()
        csv_url = None
        for res in index_meta.get("resources", []):
            if res.get("name") == "targets.simple.csv":
                csv_url = res.get("url")
                break
        if not csv_url:
            raise RuntimeError(f"targets.simple.csv not found in dataset index resources: "
                               f"{[r.get('name') for r in index_meta.get('resources', [])]}")
        print(f"[*] [OPENSANCTIONS MIRROR] fetching {csv_url} ...")
        resp = requests.get(csv_url, timeout=180, allow_redirects=True)
        resp.raise_for_status()
        csv_bytes = resp.content
        source = csv_url

    snapshot = build_snapshot(csv_bytes, source, index_meta)
    MIRROR_DIR.mkdir(parents=True, exist_ok=True)
    RAW_CSV.write_bytes(csv_bytes)
    SNAPSHOT.write_text(json.dumps(snapshot, indent=2) + "\n", encoding="utf-8")
    print(f"[+] [OPENSANCTIONS MIRROR] wrote {SNAPSHOT}")
    print(f"    entities: {snapshot['entity_count']}  license: {snapshot['license']}")
    print(f"    csv sha256: {snapshot['csv_sha256'][:16]}...  downloaded_at: {snapshot['downloaded_at']}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001 — surface the real reason, leave old snapshot intact
        print(f"[-] [OPENSANCTIONS MIRROR] failed: {exc}", file=sys.stderr)
        sys.exit(1)
