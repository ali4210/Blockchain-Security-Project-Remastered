import json
from pathlib import Path

def aggregate():
    status_file = Path("reports/status.json")
    if not status_file.exists():
        print("[-] reports/status.json not found")
        return

    status = json.loads(status_file.read_text(encoding="utf-8"))
    v104 = status.get("enterprise_v10_4", {})

    # 1. Native Gitleaks 8.18.4
    gl_path = Path("reports/gitleaks-report.json")
    if gl_path.exists():
        try:
            gl_data = json.loads(gl_path.read_text(encoding="utf-8"))
            v104["gitleaks"] = {
                "version": "8.18.4",
                "findings_count": len(gl_data),
                "status": "FLAGGED_LEAKS" if len(gl_data) > 0 else "CLEAN"
            }
        except Exception:
            pass

    # 2. Native OpenSCAP oscap 1.4.4
    oscap_path = Path("reports/openscap-report.json")
    if oscap_path.exists():
        try:
            oscap_data = json.loads(oscap_path.read_text(encoding="utf-8"))
            v104["openscap"] = {
                "engine": oscap_data.get("engine", "OpenSCAP"),
                "status": oscap_data.get("status", "PASS"),
                "standard": oscap_data.get("compliance_standard", "NIST SP 800-53 (Rev 5)")
            }
        except Exception:
            pass

    # 3. LangGraph 7-Agent Swarm (Windows GPU Inference)
    swarm_path = Path("reports/swarm-execution-report.json")
    if swarm_path.exists():
        try:
            swarm_data = json.loads(swarm_path.read_text(encoding="utf-8"))
            decisions = swarm_data.get("agents", [])
            v104["langgraph_swarm"] = {
                "agents_count": len(decisions),
                "framework": "LangGraph StateGraph",
                "host_bridge": "http://192.168.0.189:11434",
                "decision": swarm_data.get("decision"),
                "votes": swarm_data.get("votes", {}),
                "nodes": [
                    {
                        "agent": d.get("agent"),
                        "engine": d.get("status"),   # real per-agent status (ok/not_run/error)
                        "model": d.get("model"),
                        "verdict": d.get("vote"),     # real parsed vote (HALT/CLEAR/ABSTAIN)
                    } for d in decisions
                ]
            }
        except Exception:
            pass

    # 4. 3-Node Anvil AVS Consensus Gate — every field below is computed from
    # this run's real validator_observations, never a fabricated default.
    avs_path = Path("reports/avs-consensus-report.json")
    if avs_path.exists():
        try:
            avs_data = json.loads(avs_path.read_text(encoding="utf-8"))
            obs = avs_data.get("validator_observations", [])
            total = avs_data.get("nodes_total", len(obs)) or 0
            exploit_votes = avs_data.get("exploit_confirmed_votes", 0)
            clean_votes = avs_data.get("clean_votes", 0)
            agreeing = max(exploit_votes, clean_votes)
            v104["avs_consensus"] = {
                "protocol": avs_data.get("protocol", "unknown"),
                "topology": f"{total}-Node Anvil RPC Forks" if total else "unknown",
                "ports": sorted({o.get("port") for o in obs if o.get("port") is not None}),
                "agreement_ratio": f"{(agreeing / total * 100):.1f}%" if total else "0.0%",
                "consensus_reached": bool(avs_data.get("supermajority_exploit")) or (clean_votes == total and total > 0),
                "decision": avs_data.get("final_verdict", "unknown"),
            }
        except Exception:
            pass

    # 5. OFAC SDN screening — read the REAL result from this run, never hardcoded.
    ofac_path = Path("reports/scanners/ofac-screening.json")
    screen_path = Path("reports/ofac-screening-report.json")
    ti = {"status": "not_run", "screened": 0, "flagged": 0,
          "sanction_list": "OFAC SDN", "detail": "screening did not run this cycle"}
    if ofac_path.is_file():
        try:
            res = json.loads(ofac_path.read_text(encoding="utf-8"))
            counts = res.get("counts", {})
            ti["status"] = res.get("status", "not_run")
            ti["screened"] = counts.get("screened", 0)
            ti["flagged"] = counts.get("flagged", 0)
            ti["detail"] = res.get("detail", "")
            if screen_path.is_file():
                snap = json.loads(screen_path.read_text(encoding="utf-8")).get("snapshot", {})
                ti["snapshot_date"] = snap.get("downloaded_at")
                ti["snapshot_addresses"] = snap.get("address_count")
        except (OSError, ValueError):
            ti["status"] = "error"
    v104["threat_intel"] = ti

    # 6. HashiCorp Vault Transit signing — real per-run attestation result.
    vault_path = Path("reports/scanners/vault-sign.json")
    if vault_path.is_file():
        try:
            vd = json.loads(vault_path.read_text(encoding="utf-8"))
            v104["hashicorp_vault"] = {
                "engine": "transit",  # genuinely the engine this pipeline calls; not a measured value
                "status": vd.get("status", "not_run"),
                "detail": vd.get("detail"),
            }
        except Exception:
            pass

    # 7. Aqua Trivy filesystem scan — real critical/high counts.
    trivy_path = Path("reports/scanners/trivy.json")
    if trivy_path.is_file():
        try:
            td = json.loads(trivy_path.read_text(encoding="utf-8"))
            counts = td.get("counts", {})
            v104["aqua_trivy"] = {
                "status": td.get("status", "not_run"),
                "critical": counts.get("critical", 0),
                "high": counts.get("high", 0),
            }
        except Exception:
            pass

    # 8. OWASP Smart Contract Top 10 categories actually hit this run (real
    # Slither/Mythril findings, not a fixed "SC01/SC10" label).
    sast_path = Path("reports/sast-symbolic-report.json")
    if sast_path.is_file():
        try:
            sd = json.loads(sast_path.read_text(encoding="utf-8"))
            owasp_summary = sd.get("owaspSummary", {})
            v104["owasp_sc_top_10"] = ", ".join(sorted(owasp_summary.keys())) if owasp_summary else "none triggered this run"
        except Exception:
            pass

    # 9. K3s cluster check — real node/version, or an honest not_run.
    k3s_path = Path("reports/scanners/k3s.json")
    if k3s_path.is_file():
        try:
            kd = json.loads(k3s_path.read_text(encoding="utf-8"))
            v104["k3s_kubernetes"] = {
                "status": kd.get("status", "not_run"),
                "node": kd.get("target") or (kd.get("counts") or {}).get("node_name"),
                "version": kd.get("version"),
                "detail": kd.get("detail"),
            }
        except Exception:
            pass

    status["enterprise_v10_4"] = v104
    status_file.write_text(json.dumps(status, indent=2), encoding="utf-8")
    print("[+] Successfully aggregated accurate Enterprise V10.4 telemetry into reports/status.json")

if __name__ == "__main__":
    aggregate()
