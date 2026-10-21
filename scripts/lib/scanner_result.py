#!/usr/bin/env python3
"""Shared result contract: every scanner writes reports/scanners/<name>.json.

status: ok       tool really ran and produced a parseable report
        not_run  tool/content missing (never faked)
        error    tool ran but failed, or its output cannot be trusted
CLI (for bash wrappers):
  scanner_result.py NAME TOOL STATUS [--version V] [--target T] [--detail D]
                    [--counts JSON] [--raw PATH] [--extra JSON]
"""
import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RESULTS = ROOT / "reports" / "scanners"
RAW = ROOT / "reports" / "raw"
STATUSES = ("ok", "not_run", "error")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _rel(path):
    p = Path(path)
    try:
        return str(p.resolve().relative_to(ROOT))
    except ValueError:
        return str(p)


def write_result(name, tool, status, *, version=None, target=None, counts=None,
                 raw_report=None, detail=None, extra=None):
    if status not in STATUSES:
        raise ValueError(f"bad status {status!r}")
    RESULTS.mkdir(parents=True, exist_ok=True)
    raw = Path(raw_report) if raw_report else None
    rec = {
        "name": name, "tool": tool, "status": status, "version": version,
        "target": target, "counts": counts or {},
        "raw_report": _rel(raw) if raw else None,
        "raw_sha256": sha256_file(raw) if raw and raw.is_file() else None,
        "detail": detail,
        "finished_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    if extra:
        rec.update(extra)
    (RESULTS / f"{name}.json").write_text(json.dumps(rec, indent=2) + "\n", encoding="utf-8")
    mark = {"ok": "+", "not_run": "!", "error": "-"}[status]
    line = f"    [{mark}] {name}: {status}"
    if counts:
        line += f" {counts}"
    if detail:
        line += f" | {detail}"
    print(line)
    return rec


def load_all():
    """name -> result dict for every scanner result of the current run."""
    out = {}
    if RESULTS.is_dir():
        for p in sorted(RESULTS.glob("*.json")):
            try:
                out[p.stem] = json.loads(p.read_text(encoding="utf-8"))
            except ValueError:
                out[p.stem] = {"name": p.stem, "status": "error", "detail": "unreadable result file", "counts": {}}
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("name")
    ap.add_argument("tool")
    ap.add_argument("status", choices=STATUSES)
    ap.add_argument("--version")
    ap.add_argument("--target")
    ap.add_argument("--detail")
    ap.add_argument("--counts", default="{}")
    ap.add_argument("--raw")
    ap.add_argument("--extra", default="{}")
    a = ap.parse_args()
    write_result(a.name, a.tool, a.status, version=a.version, target=a.target,
                 counts=json.loads(a.counts), raw_report=a.raw, detail=a.detail,
                 extra=json.loads(a.extra))


if __name__ == "__main__":
    main()
