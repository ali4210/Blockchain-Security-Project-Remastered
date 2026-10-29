#!/usr/bin/env python3
"""Phase 3b CLI wrapper: fetch one real on-chain contract via Etherscan's
real V2 API (src/onchain/etherscan_client.py) and report through the same
reports/scanners/<name>.json contract every other scanner in this pipeline
uses.

Usage:
  python3 scripts/fetch-etherscan-contract.py --address 0x...
  python3 scripts/fetch-etherscan-contract.py --address 0x... --chain-id 1

On a real, verified, single-file success, prints the real
target_contract_path -- pass that straight to TARGET_CONTRACT for
run-sast-symbolic.py / swarm_orchestrator.py, exactly like any local fixture.
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
from scanner_result import write_result  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.onchain.etherscan_client import fetch_contract, DEFAULT_CHAIN_ID  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--address", required=True, help="Contract address to fetch")
    ap.add_argument("--chain-id", default=DEFAULT_CHAIN_ID, help="Etherscan V2 chainid (default: 1, Ethereum mainnet)")
    args = ap.parse_args()

    print(f"[+] [ONCHAIN] Fetching {args.address} from Etherscan (chainid={args.chain_id})...")
    result = fetch_contract(args.address, args.chain_id)

    print(f"    -> status={result['status']} verified={result.get('verified')} :: {result['detail']}")
    if result.get("target_contract_path"):
        print(f"    -> target_contract_path={result['target_contract_path']}")
    if result.get("creation_error"):
        print(f"    -> [!] creation metadata not available: {result['creation_error']}")
    elif result.get("creation"):
        c = result["creation"]
        print(f"    -> creator={c.get('contractCreator')} created_in_tx={c.get('txHash')}")

    # creationBytecode can be large and isn't the point of this lightweight
    # scanner_result record (creator/txHash/block are) -- dropped here only,
    # never from fetch_contract()'s own real return value.
    extra = {k: v for k, v in result.items() if k not in ("status", "detail", "address")}
    if extra.get("creation"):
        extra["creation"] = {k: v for k, v in extra["creation"].items() if k != "creationBytecode"}

    write_result("etherscan-fetch", "etherscan", result["status"],
                 target=result["address"],
                 counts={"verified": int(bool(result.get("verified")))},
                 detail=result["detail"],
                 extra=extra)
    return 0 if result["status"] in ("ok", "not_run") else 1


if __name__ == "__main__":
    sys.exit(main())
