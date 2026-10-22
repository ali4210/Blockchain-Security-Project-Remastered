#!/usr/bin/env python3
import os
import json
import uuid
import requests
from requests.auth import HTTPBasicAuth
from datetime import datetime, timezone

# 1. Load credentials from .env
env_vars = {}
env_file = ".env"
if os.path.exists(env_file):
    with open(env_file) as f:
        for line in f:
            if "=" in line and not line.strip().startswith("#"):
                k, v = line.strip().split("=", 1)
                env_vars[k.strip()] = v.strip().strip('"').strip("'")

ELASTIC_USER = os.getenv("ELASTIC_USER") or env_vars.get("ELASTIC_USER", "elastic")
ELASTIC_PASS = os.getenv("ELASTIC_PASSWORD") or env_vars.get("ELASTIC_PASSWORD", "ElasticAdminPass123")
ELASTIC_URL = os.getenv("ELASTICSEARCH_URL", "http://192.168.0.150:9200")
INDEX_NAME = "blockchain-soc-events"

def get_timestamp():
    return datetime.now(timezone.utc).isoformat()

def bulk_index_docs(documents):
    if not documents:
        print("[*] No documents collected.")
        return 0

    bulk_payload = ""
    for doc in documents:
        meta = {"index": {"_index": INDEX_NAME}}
        bulk_payload += json.dumps(meta) + "\n" + json.dumps(doc) + "\n"

    headers = {"Content-Type": "application/x-ndjson"}
    auth = HTTPBasicAuth(ELASTIC_USER, ELASTIC_PASS)
    try:
        r = requests.post(
            f"{ELASTIC_URL}/_bulk",
            headers=headers,
            data=bulk_payload,
            auth=auth,
            timeout=15
        )
        if r.status_code == 200:
            res = r.json()
            items = res.get("items", [])
            print(f"[+] Successfully indexed {len(items)} granular events into '{INDEX_NAME}'.")
            return len(items)
        else:
            print(f"[!] Bulk index failed with status {r.status_code}: {r.text}")
            return 0
    except Exception as e:
        print(f"[!] Connection failed: {e}")
        return 0

def collect_events():
    events = []
    run_id = os.getenv("PIPELINE_RUN_ID", str(uuid.uuid4())[:8])
    target_contract = os.getenv("TARGET_CONTRACT", "contracts/solidity/SecureVault.sol")
    target_name = target_contract.split("/")[-1]
    ts = get_timestamp()

    # 1. Zone 1: Gitleaks Individual Leaks
    gl_file = "reports/gitleaks-report.json"
    if os.path.exists(gl_file):
        try:
            with open(gl_file) as f:
                gl_data = json.load(f)
                for item in gl_data:
                    events.append({
                        "@timestamp": ts,
                        "event_category": "secret-leak",
                        "event_kind": "alert",
                        "log_level": "WARN",
                        "pipeline_run_id": run_id,
                        "pipeline_target": target_name,
                        "tool_name": "Gitleaks",
                        "rule_id": item.get("RuleID"),
                        "file_path": item.get("File"),
                        "file_line": item.get("StartLine"),
                        "entropy": item.get("Entropy"),
                        "message": f"High entropy secret flagged by rule '{item.get('RuleID')}' in {item.get('File')}:{item.get('StartLine')}"
                    })
        except Exception as e:
            print(f"[!] Parsing {gl_file}: {e}")

    # 2. Zone 2: Slither & Mythril SARIF Findings
    sarif_file = "reports/sast-symbolic-report.sarif"
    if os.path.exists(sarif_file):
        try:
            with open(sarif_file) as f:
                sarif = json.load(f)
                runs = sarif.get("runs", [])
                for run in runs:
                    tool = run.get("tool", {}).get("driver", {}).get("name", "SAST-Engine")
                    for res in run.get("results", []):
                        level = res.get("level", "warning").upper()
                        msg_text = res.get("message", {}).get("text", "")
                        events.append({
                            "@timestamp": ts,
                            "event_category": "vulnerability",
                            "event_kind": "alert",
                            "log_level": "ERROR" if level in ["ERROR", "CRITICAL"] else "WARN",
                            "pipeline_run_id": run_id,
                            "pipeline_target": target_name,
                            "tool_name": tool,
                            "rule_id": res.get("ruleId"),
                            "vulnerability_category": res.get("properties", {}).get("owasp_category", "Smart Contract Flaw"),
                            "message": msg_text,
                            "dread_score": 8.4 if "Reentrancy" in msg_text else 0.0
                        })
        except Exception as e:
            print(f"[!] Parsing {sarif_file}: {e}")

    # 3. Zone 2: OWASP ZAP DAST Alerts
    zap_file = "reports/dast/zap-report.json"
    if os.path.exists(zap_file):
        try:
            with open(zap_file) as f:
                zap = json.load(f)
                site_alerts = zap.get("site", [{}])[0].get("alerts", [])
                for alert in site_alerts:
                    events.append({
                        "@timestamp": ts,
                        "event_category": "dast-alert",
                        "event_kind": "alert",
                        "log_level": "WARN",
                        "pipeline_run_id": run_id,
                        "pipeline_target": target_name,
                        "tool_name": "OWASP-ZAP",
                        "vulnerability_name": alert.get("alert"),
                        "risk_confidence": alert.get("confidence"),
                        "risk_level": alert.get("riskdesc"),
                        "message": alert.get("desc")[:250] if alert.get("desc") else "DAST finding"
                    })
        except Exception as e:
            print(f"[!] Parsing {zap_file}: {e}")

    # 4. Zone 3: LangGraph Swarm Agents Telemetry -- real per-agent votes from
    # this run's actual swarm execution, never a fixed agent/model/verdict list.
    swarm_file = "reports/swarm-execution-report.json"
    if os.path.exists(swarm_file):
        try:
            with open(swarm_file) as f:
                swarm = json.load(f)
                for ag in swarm.get("agents", []):
                    vote = ag.get("vote", "ABSTAIN")
                    status = ag.get("status", "not_run")
                    events.append({
                        "@timestamp": ts,
                        "event_category": "ai-swarm",
                        "event_kind": "event",
                        "log_level": "ERROR" if vote == "HALT" else ("WARN" if status != "ok" else "INFO"),
                        "pipeline_run_id": run_id,
                        "pipeline_target": target_name,
                        "tool_name": "LangGraph-Swarm",
                        "agent_name": ag.get("agent"),
                        "agent_id": ag.get("agent_id"),
                        "agent_model": ag.get("model"),
                        "agent_status": status,
                        "agent_verdict": vote,
                        "message": f"{ag.get('agent')} ({status}) executed evaluation using {ag.get('model')}. Verdict emitted: {vote}"
                    })
        except Exception as e:
            print(f"[!] Parsing {swarm_file}: {e}")

    # 5. Zone 4: BFT AVS Consensus Nodes -- real per-validator observations
    # from this run's actual 3-node Anvil exploit execution, never a fixed
    # "confirmed block state consistency" claim regardless of outcome.
    avs_file = "reports/avs-consensus-report.json"
    if os.path.exists(avs_file):
        try:
            with open(avs_file) as f:
                avs = json.load(f)
                total = avs.get("nodes_total", 0)
                exploit_votes = avs.get("exploit_confirmed_votes", 0)
                for obs in avs.get("validator_observations", []):
                    vote = obs.get("vote", "INDETERMINATE")
                    events.append({
                        "@timestamp": ts,
                        "event_category": "avs-consensus",
                        "event_kind": "event",
                        "log_level": "ERROR" if vote == "EXPLOIT_CONFIRMED" else ("WARN" if vote == "INDETERMINATE" else "INFO"),
                        "pipeline_run_id": run_id,
                        "pipeline_target": target_name,
                        "tool_name": "Anvil-BFT-Sandbox",
                        "validator_id": obs.get("validator"),
                        "validator_rpc_port": obs.get("port"),
                        "validator_vote": vote,
                        "consensus_quorum": f"{exploit_votes}/{total} ({(exploit_votes / total * 100) if total else 0:.1f}%)",
                        "message": f"Validator node {obs.get('validator')} on port {obs.get('port')} voted {vote} "
                                   f"({avs.get('final_verdict', 'unknown')})"
                    })
        except Exception as e:
            print(f"[!] Parsing {avs_file}: {e}")

    return events

if __name__ == "__main__":
    docs = collect_events()
    bulk_index_docs(docs)
