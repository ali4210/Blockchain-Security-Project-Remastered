#!/usr/bin/env python3
import os
import json
import uuid
import requests
import xml.etree.ElementTree as ET
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

    # 2. Zone 2: Slither SARIF Findings. HONEST NOTE: despite this block's
    # original "Slither & Mythril SARIF" framing, the real SARIF file
    # (reports/sast-symbolic-report.sarif) genuinely only ever carries a
    # single run with driver.name="Slither" in this pipeline's current
    # architecture -- verified directly against the real file, which has
    # exactly one run and 2 results, both Slither's. Mythril's findings are
    # never exported to SARIF at all; they only exist in
    # reports/sast-symbolic-report.json with a clean per-finding "engine"
    # field (see block 2b below). Pre-existing documents already indexed
    # under tool_name="Slither-Mythril-Hybrid-SAST" from an earlier pipeline
    # architecture are historical and untouched by this fix -- this block,
    # as written, only ever tags real Slither findings correctly, and
    # produces nothing for Mythril (hence block 2b).
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

    # 2b. Mythril findings -- real per-finding events with a genuinely
    # distinct tool_name="Mythril" (confirmed: reports/sast-symbolic-report.json's
    # findings carry a real, per-finding "engine" field that cleanly
    # distinguishes Slither from Mythril -- this is a real split the data
    # supports, not a renamed blend). Only Mythril's rows are taken here;
    # Slither's half of this same file is skipped to avoid double-counting
    # what block 2 above already indexes from the SARIF.
    sast_json_file = "reports/sast-symbolic-report.json"
    if os.path.exists(sast_json_file):
        try:
            with open(sast_json_file) as f:
                for finding in json.load(f).get("findings", []):
                    if finding.get("engine") != "Mythril":
                        continue
                    impact = (finding.get("impact") or "").upper()
                    events.append({
                        "@timestamp": ts,
                        "event_category": "vulnerability",
                        "event_kind": "alert",
                        "log_level": "ERROR" if impact in ("CRITICAL", "HIGH") else "WARN",
                        "pipeline_run_id": run_id,
                        "pipeline_target": target_name,
                        "tool_name": "Mythril",
                        "rule_id": finding.get("swc"),
                        "vulnerability_category": finding.get("owasp_category", "Smart Contract Flaw"),
                        "severity": impact,
                        "message": finding.get("description") or finding.get("check", "Mythril finding")
                    })
        except Exception as e:
            print(f"[!] Parsing {sast_json_file}: {e}")

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

    # 6. Section A: Consensus-attack findings (reorg / concentration / eclipse /
    # selfish-mining) -- real triggered checks from this run's actual
    # chain_attack_monitor.py result, never a fixed set regardless of outcome.
    consensus_file = "reports/consensus-attack-findings.json"
    if os.path.exists(consensus_file):
        try:
            with open(consensus_file) as f:
                for finding in json.load(f):
                    if not finding.get("triggered"):
                        continue
                    sev = finding.get("severity") or finding.get("threat_level") or "UNKNOWN"
                    events.append({
                        "@timestamp": ts,
                        "event_category": "consensus-attack",
                        "event_kind": "alert",
                        "log_level": "ERROR" if "CRITICAL" in sev.upper() else "WARN",
                        "pipeline_run_id": run_id,
                        "pipeline_target": target_name,
                        "tool_name": "chain-attack-monitor",
                        "metric": finding.get("metric"),
                        "threshold": finding.get("threshold"),
                        "observed_value": finding.get("observed_value"),
                        "severity_or_threat_level": sev,
                        "message": f"{finding.get('metric')} triggered: observed={finding.get('observed_value')} "
                                   f"threshold={finding.get('threshold')} ({sev})"
                    })
        except Exception as e:
            print(f"[!] Parsing {consensus_file}: {e}")

    # 7. Section B: Flash-loan / front-running findings -- real AST-heuristic
    # findings from this run's actual flashloan_detector.py result.
    flashloan_file = "reports/flashloan-findings.json"
    if os.path.exists(flashloan_file):
        try:
            with open(flashloan_file) as f:
                for t in json.load(f).get("targets", []):
                    for finding in t.get("flashloan_findings", []):
                        events.append({
                            "@timestamp": ts, "event_category": "defi-flashloan", "event_kind": "alert",
                            "log_level": "WARN", "pipeline_run_id": run_id, "pipeline_target": target_name,
                            "tool_name": "flashloan-detector", "finding_kind": "flash-loan-shape",
                            "target_contract": t.get("target"), "function_name": finding.get("function"),
                            "message": finding.get("detail", "")
                        })
                    for finding in t.get("frontrunning_findings", []):
                        events.append({
                            "@timestamp": ts, "event_category": "defi-frontrunning", "event_kind": "alert",
                            "log_level": "WARN", "pipeline_run_id": run_id, "pipeline_target": target_name,
                            "tool_name": "flashloan-detector", "finding_kind": "front-running-exposure",
                            "target_contract": t.get("target"), "function_name": finding.get("function"),
                            "message": finding.get("detail", "")
                        })
        except Exception as e:
            print(f"[!] Parsing {flashloan_file}: {e}")

    # 8. Section C: Rug-pull findings -- real FAILING checks only from this
    # run's actual rugpull_detector.py result (not_applicable/pass are not
    # events; nothing is invented for a contract with no rug-pull surface).
    rugpull_file = "reports/rugpull-findings.json"
    if os.path.exists(rugpull_file):
        try:
            with open(rugpull_file) as f:
                for t in json.load(f).get("targets", []):
                    for c in t.get("checks", []):
                        if c.get("result") != "fail":
                            continue
                        events.append({
                            "@timestamp": ts, "event_category": "defi-rugpull", "event_kind": "alert",
                            "log_level": "WARN", "pipeline_run_id": run_id, "pipeline_target": target_name,
                            "tool_name": "rugpull-detector", "check_name": c.get("check"),
                            "target_contract": t.get("target"), "message": c.get("justification", "")
                        })
        except Exception as e:
            print(f"[!] Parsing {rugpull_file}: {e}")

    # 9. Section F: Echidna property-based fuzzing -- real FALSIFIED properties
    # only from this run's actual reports/echidna-report.json.
    echidna_file = "reports/echidna-report.json"
    if os.path.exists(echidna_file):
        try:
            with open(echidna_file) as f:
                for prop in json.load(f).get("properties", []):
                    if prop.get("passed"):
                        continue
                    events.append({
                        "@timestamp": ts, "event_category": "echidna-fuzzing", "event_kind": "alert",
                        "log_level": "WARN", "pipeline_run_id": run_id, "pipeline_target": target_name,
                        "tool_name": "echidna", "property_name": prop.get("name"),
                        "message": prop.get("detail", "")
                    })
        except Exception as e:
            print(f"[!] Parsing {echidna_file}: {e}")

    # 10. Section E: Vyper compile + basic static check -- real reentrancy-
    # shaped findings only from this run's actual reports/vyper-check-report.json.
    vyper_file = "reports/vyper-check-report.json"
    if os.path.exists(vyper_file):
        try:
            with open(vyper_file) as f:
                vdata = json.load(f)
                for finding in vdata.get("reentrancy_shaped_findings", []):
                    events.append({
                        "@timestamp": ts, "event_category": "vyper-check", "event_kind": "alert",
                        "log_level": "WARN", "pipeline_run_id": run_id, "pipeline_target": target_name,
                        "tool_name": "vyper", "function_name": finding.get("function"),
                        "target_contract": vdata.get("target"), "message": finding.get("detail", "")
                    })
        except Exception as e:
            print(f"[!] Parsing {vyper_file}: {e}")

    # 11. container-trivy -- real per-vulnerability rows from this run's actual
    # reports/raw/trivy-report.json (Trivy's own native JSON, has real
    # per-finding granularity unlike most of the scanner_result summaries below).
    trivy_file = "reports/raw/trivy-report.json"
    if os.path.exists(trivy_file):
        try:
            with open(trivy_file) as f:
                for result in json.load(f).get("Results", []):
                    target = result.get("Target")
                    for v in (result.get("Vulnerabilities") or []):
                        sev = (v.get("Severity") or "UNKNOWN").upper()
                        events.append({
                            "@timestamp": ts, "event_category": "container-trivy", "event_kind": "alert",
                            "log_level": "ERROR" if sev in ("CRITICAL", "HIGH") else "WARN",
                            "pipeline_run_id": run_id, "pipeline_target": target_name,
                            "tool_name": "Trivy", "vulnerability_id": v.get("VulnerabilityID"),
                            "package_name": v.get("PkgName"), "severity": sev, "scanned_target": target,
                            "message": v.get("Title") or f"{v.get('VulnerabilityID')} in {v.get('PkgName')}"
                        })
        except Exception as e:
            print(f"[!] Parsing {trivy_file}: {e}")

    # 12. sca-dependency -- one real summary event from reports/scanners/sca.json's
    # real counts (no itemized per-package advisory list exists in this
    # pipeline's output, same honest limitation ingest-defectdojo.py's
    # build_sca_findings already documents -- only emitted when there is a
    # genuine active advisory or npm-audit high/critical count, never for a clean run).
    sca_file = "reports/scanners/sca.json"
    if os.path.exists(sca_file):
        try:
            with open(sca_file) as f:
                sca = json.load(f)
                counts = sca.get("counts", {})
                crit, high = counts.get("npmAuditCritical", 0), counts.get("npmAuditHigh", 0)
                active = counts.get("activeAdvisories", 0)
                if sca.get("status") == "ok" and (active > 0 or crit > 0 or high > 0):
                    events.append({
                        "@timestamp": ts, "event_category": "sca-dependency", "event_kind": "alert",
                        "log_level": "ERROR" if crit > 0 else "WARN",
                        "pipeline_run_id": run_id, "pipeline_target": target_name,
                        "tool_name": "osv+nvd", "active_advisories": active,
                        "npm_audit_critical": crit, "npm_audit_high": high,
                        "matched_packages": counts.get("matchedPackages", 0),
                        "message": f"{active} active advisories across {counts.get('matchedPackages', 0)} "
                                   f"matched package(s); npm audit {crit} critical / {high} high"
                    })
        except Exception as e:
            print(f"[!] Parsing {sca_file}: {e}")

    # 13. compliance-openscap -- real failed SCAP rules from the raw XML, same
    # parsing ingest-defectdojo.py's build_openscap_findings already uses. On
    # this host (profile/platform mismatch, 0 rules genuinely scored) this
    # correctly produces zero events -- not a bug, an honest reflection.
    oscap_file = "reports/raw/oscap-results.xml"
    if os.path.exists(oscap_file):
        try:
            root = ET.parse(oscap_file).getroot()
            for rr in root.findall(".//{*}rule-result"):
                if (rr.findtext("{*}result") or "").strip() != "fail":
                    continue
                rule_id = rr.get("idref", "unknown-rule")
                events.append({
                    "@timestamp": ts, "event_category": "compliance-openscap", "event_kind": "alert",
                    "log_level": "WARN", "pipeline_run_id": run_id, "pipeline_target": target_name,
                    "tool_name": "OpenSCAP", "rule_id": rule_id,
                    "message": f"SCAP rule {rule_id} failed evaluation"
                })
        except ET.ParseError as e:
            print(f"[!] Parsing {oscap_file}: {e}")

    # 14. code-quality-sonar -- one real event only when the real quality gate
    # is ERROR (same gate ingest-defectdojo.py's build_sonar_findings checks).
    sonar_file = "reports/scanners/sonar.json"
    if os.path.exists(sonar_file):
        try:
            with open(sonar_file) as f:
                sonar = json.load(f)
                if sonar.get("gate") == "ERROR":
                    events.append({
                        "@timestamp": ts, "event_category": "code-quality-sonar", "event_kind": "alert",
                        "log_level": "WARN", "pipeline_run_id": run_id, "pipeline_target": target_name,
                        "tool_name": "SonarQube", "project": sonar.get("project"),
                        "message": sonar.get("detail", "SonarQube quality gate: ERROR")
                    })
        except Exception as e:
            print(f"[!] Parsing {sonar_file}: {e}")

    # 15. readiness-gate -- one real event only when the real decision is
    # "block" (same gate ingest-defectdojo.py's build_readiness_findings checks).
    readiness_file = "reports/scanners/readiness.json"
    if os.path.exists(readiness_file):
        try:
            with open(readiness_file) as f:
                readiness = json.load(f)
                if readiness.get("decision") == "block":
                    events.append({
                        "@timestamp": ts, "event_category": "readiness-gate", "event_kind": "alert",
                        "log_level": "WARN", "pipeline_run_id": run_id, "pipeline_target": target_name,
                        "tool_name": "production-readiness",
                        "message": readiness.get("detail", "production readiness gate: BLOCK")
                    })
        except Exception as e:
            print(f"[!] Parsing {readiness_file}: {e}")

    # 16. ofac-screening -- one real event per genuinely FLAGGED address from
    # this run's actual screening (same convention as
    # ingest-defectdojo.py's build_ofac_findings: never for a clean address).
    ofac_file = "reports/ofac-screening-report.json"
    if os.path.exists(ofac_file):
        try:
            with open(ofac_file) as f:
                for row in json.load(f).get("screened", []):
                    if not row.get("flagged"):
                        continue
                    events.append({
                        "@timestamp": ts, "event_category": "ofac-screening", "event_kind": "alert",
                        "log_level": "ERROR", "pipeline_run_id": run_id, "pipeline_target": target_name,
                        "tool_name": "ofac-sdn", "screened_address": row.get("address"),
                        "risk_tier": row.get("risk_tier"),
                        "message": f"OFAC SDN match: {row.get('entity') or 'unknown entity'} ({row.get('reason', '')})"
                    })
        except Exception as e:
            print(f"[!] Parsing {ofac_file}: {e}")

    # 17-21. Infra/attestation checks (vault-signing, k8s-k3s, wallet-presign,
    # llm-langfuse, hsm-signing, quorum-signing): these have no per-item
    # findings list -- a single real status IS the signal. A real FAILURE is
    # the alert; a healthy "ok" run emits nothing, same "don't spam a clean
    # result" convention as every finding-based block above.
    for scanner_file, category, tool_label in (
        ("reports/scanners/vault-sign.json", "vault-signing", "HashiCorp-Vault-Transit"),
        ("reports/scanners/k3s.json", "k8s-k3s", "kubectl"),
        ("reports/scanners/presign-sim.json", "wallet-presign", "presign-simulator"),
        ("reports/scanners/langfuse.json", "llm-langfuse", "Langfuse"),
        ("reports/scanners/hsm-signer.json", "hsm-signing", "SoftHSM2-PKCS11"),
        ("reports/scanners/quorum-signer.json", "quorum-signing", "Shamir-MPC-JointSign"),
    ):
        if not os.path.exists(scanner_file):
            continue
        try:
            with open(scanner_file) as f:
                res = json.load(f)
                if res.get("status") == "ok":
                    continue  # healthy: no alert to raise
                events.append({
                    "@timestamp": ts, "event_category": category, "event_kind": "alert",
                    "log_level": "ERROR", "pipeline_run_id": run_id, "pipeline_target": target_name,
                    "tool_name": tool_label, "scanner_status": res.get("status"),
                    "message": res.get("detail", f"{category}: {res.get('status')}")
                })
        except Exception as e:
            print(f"[!] Parsing {scanner_file}: {e}")

    return events

if __name__ == "__main__":
    docs = collect_events()
    bulk_index_docs(docs)
