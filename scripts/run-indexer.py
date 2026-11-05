#!/usr/bin/env python3
"""Zone 1: real on-chain indexer scanner wrapper.

Runs src/onchain/indexer.py's real, short-lived indexing pass (see that
module's own HONEST SCOPE note for exactly what "continuous monitoring"
does and does not mean here) and reports via the shared scanner_result
contract.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
from scanner_result import ROOT, write_result  # noqa: E402
from src.onchain.indexer import run_indexer  # noqa: E402


def main():
    print("[+] [ZONE 1] Real on-chain indexer (short-lived per-run Anvil + Elasticsearch)...")
    result = run_indexer()
    report_file = ROOT / "reports" / "indexer-report.json"
    report_file.parent.mkdir(parents=True, exist_ok=True)
    report_file.write_text(json.dumps(result, indent=2, default=str) + "\n", encoding="utf-8")

    status = result.get("status", "error")
    if status != "ok":
        return write_result("indexer", "custom-onchain-indexer", status, detail=result.get("detail"))

    detail = (f"{result['documents_indexed']}/{result['documents_built']} doc(s) indexed into "
              f"{result['es_index']} ({result['decoded_events']} decoded event(s), "
              f"{result['transaction_activity_docs']} transaction-activity doc(s))")
    print(f"    -> {detail}")
    return write_result("indexer", "custom-onchain-indexer", "ok", raw_report=report_file,
                        detail=detail,
                        counts={"documents_indexed": result["documents_indexed"],
                                "decoded_events": result["decoded_events"],
                                "transaction_activity_docs": result["transaction_activity_docs"]})


if __name__ == "__main__":
    main()
