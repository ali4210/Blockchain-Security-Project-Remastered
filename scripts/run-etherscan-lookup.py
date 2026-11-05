#!/usr/bin/env python3
"""Zone 1: real Etherscan V2 API lookup for a deployed on-chain artifact.

Advances the "continuous monitoring for deployed contracts" syllabus gap
(Topic 124) by fetching real, live data about a real deployed address --
verification status + source, recent transaction history, current balance,
and recent event logs -- via src/onchain/etherscan_client.py.

Key handling: the API key is read ONLY from HashiCorp Vault at
secret/data/soc/etherscan (field: api_key) at runtime, via VAULT_ADDR/
VAULT_TOKEN -- never from .env or any tracked file. If Vault is
unreachable, unauthenticated, or the secret is missing, this is honestly
not_run, never a fabricated result.

Target address:
  * TARGET_CONTRACT_ADDRESS env (optionally TARGET_CONTRACT_CHAIN_ID,
    default "1") if set -- a real address the operator wants inspected.
  * otherwise a DEMONSTRATION canary: a real, long-verified, extremely
    well-known public contract (WETH9 on Ethereum mainnet) -- NOT one of
    this project's own fixtures. Same honest "demonstration-canary" mode
    convention as run-ofac-screening.py / run-kyc-screening.py, chosen
    because this project has no funded testnet deployer key to put its
    own VulnerableVault/SecureVault on a public chain (see this script's
    own HONEST SCOPE note below).

HONEST SCOPE: this project's own contracts (VulnerableVault.sol,
SecureVault.sol, etc.) are NOT deployed to any public chain -- only to
ephemeral local Anvil instances (src/consensus/avs_consensus.py,
src/onchain/indexer.py), which Etherscan cannot see. Querying a real
public contract proves this live API integration genuinely works
end-to-end; it does not mean this project's own artifacts are under
Etherscan monitoring yet. That remains a real, documented gap until a
funded deployer key is provided.

Honest status via scanner_result:
  not_run  -- no Vault key, or Vault unreachable
  error    -- Etherscan reachable but every real call failed
  ok       -- at least the core verification lookup really ran
"""
import json
import os
import sys
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
from scanner_result import ROOT, write_result  # noqa: E402
from src.onchain import etherscan_client as ec  # noqa: E402

# WETH9 -- deployed 2017-12-20, verified on Etherscan since shortly after,
# among the most-interacted-with contracts on Ethereum. Used purely to
# demonstrate this client against a real, stable, rich-history target.
DEMO_CANARY_ADDRESS = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
DEMO_CANARY_CHAIN_ID = "1"

VAULT_ADDR = os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
VAULT_TOKEN = os.environ.get("VAULT_TOKEN")


def _vault_etherscan_key():
    """Real Vault read, never a .env fallback for this one secret."""
    if not VAULT_TOKEN:
        return None, "VAULT_TOKEN not set"
    try:
        resp = requests.get(
            f"{VAULT_ADDR}/v1/secret/data/soc/etherscan",
            headers={"X-Vault-Token": VAULT_TOKEN}, timeout=5,
        )
    except requests.exceptions.RequestException as exc:
        return None, f"vault unreachable: {str(exc)[:150]}"
    if resp.status_code != 200:
        return None, f"secret/data/soc/etherscan not found (HTTP {resp.status_code})"
    try:
        key = resp.json().get("data", {}).get("data", {}).get("api_key")
    except ValueError:
        return None, "unparseable vault response"
    if not key:
        return None, "vault secret present but api_key field empty"
    return key, None


def target():
    addr = os.environ.get("TARGET_CONTRACT_ADDRESS", "").strip()
    if addr:
        return addr, os.environ.get("TARGET_CONTRACT_CHAIN_ID", "1"), False
    return DEMO_CANARY_ADDRESS, DEMO_CANARY_CHAIN_ID, True


def main():
    print("[+] [ZONE 1] Etherscan V2 API lookup for deployed artifact...")
    key, err = _vault_etherscan_key()
    if err:
        return write_result("etherscan-lookup", "etherscan-v2-api", "not_run", detail=err)
    os.environ["ETHERSCAN_API_KEY"] = key

    addr, chain_id, is_demo = target()
    print(f"    -> target: {addr} (chainid={chain_id})"
          + (" [DEMONSTRATION canary -- not one of this project's own contracts]" if is_demo else ""))

    source_result, source_error = ec.get_source_code(addr, chain_id)
    creation, creation_error = ec.get_contract_creation(addr, chain_id)
    balance, balance_error = ec.get_balance(addr, chain_id)
    txs, tx_error = ec.get_tx_list(addr, chain_id, limit=10)
    logs, logs_error = ec.get_event_logs(addr, chain_id, limit=25)

    if source_error and balance_error and tx_error and logs_error:
        # every real call failed -- genuinely can't trust anything here
        return write_result("etherscan-lookup", "etherscan-v2-api", "error",
                            target=addr, detail=f"all lookups failed; source: {source_error}")

    is_verified = bool(source_result and source_result.get("SourceCode"))
    report = {
        "mode": "demonstration-canary" if is_demo else "operator-supplied",
        "address": addr,
        "chain_id": chain_id,
        "verified": is_verified,
        "contract_name": (source_result or {}).get("ContractName") if is_verified else None,
        "compiler_version": (source_result or {}).get("CompilerVersion") if is_verified else None,
        "source_lookup_error": source_error,
        "creation": creation,
        "creation_error": creation_error,
        "balance_wei": balance,
        "balance_error": balance_error,
        "recent_transactions": (txs or [])[:10],
        "tx_count_fetched": len(txs or []),
        "tx_error": tx_error,
        "recent_event_logs": (logs or [])[:25],
        "log_count_fetched": len(logs or []),
        "logs_error": logs_error,
    }
    report_file = ROOT / "reports" / "etherscan-lookup-report.json"
    report_file.parent.mkdir(parents=True, exist_ok=True)
    report_file.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    print(f"    -> verified={is_verified} balance_wei={balance} "
          f"tx_fetched={len(txs or [])} logs_fetched={len(logs or [])}")

    note = " (DEMONSTRATION canary: real public contract, not one of this project's own)" if is_demo else ""
    detail = (f"address {addr} on chain {chain_id}: verified={is_verified}, "
              f"{len(txs or [])} recent tx(s), {len(logs or [])} recent log(s){note}")
    return write_result("etherscan-lookup", "etherscan-v2-api", "ok",
                        target=addr, raw_report=report_file, detail=detail,
                        counts={"tx_fetched": len(txs or []), "logs_fetched": len(logs or [])},
                        extra={"mode": report["mode"]})


if __name__ == "__main__":
    main()
