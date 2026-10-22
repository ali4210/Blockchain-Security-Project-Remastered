
def get_latest_jira_ticket():
    import os, re
    ticket_file = "reports/latest-jira-ticket.txt"
    if os.path.exists(ticket_file):
        try:
            with open(ticket_file, "r", encoding="utf-8") as f:
                val = f.read().strip()
                if val.startswith("KAN-"):
                    return val
        except Exception:
            pass
    for candidate in ["reports/stix/latest-incident-stix.json", "reports/status.json"]:
        if os.path.exists(candidate):
            try:
                with open(candidate, "r", encoding="utf-8") as f:
                    matches = re.findall(r"KAN-[0-9]+", f.read())
                    if matches:
                        return matches[-1]
            except Exception:
                pass
    return "KAN-23"

import json
import os
import sys
import socket
import requests
from pathlib import Path
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading

# Same impact -> DREAD-style score mapping as run-incident-abort.py's
# IMPACT_SCORE/IMPACT_RANK, so both tools report the same number for the
# same run instead of one being a fixed SECURE-flag guess.
_IMPACT_SCORE = {"CRITICAL": 9.5, "HIGH": 8.0, "MEDIUM": 5.5, "LOW": 3.0,
                 "INFORMATIONAL": 1.0, "INFO": 1.0}
_IMPACT_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFORMATIONAL": 1, "INFO": 1}


def _compute_dread_score():
    sast_path = Path("reports/sast-symbolic-report.json")
    if not sast_path.is_file():
        return 0.0
    try:
        sast = json.loads(sast_path.read_text(encoding="utf-8"))
    except Exception:
        return 0.0
    findings = sast.get("findings", [])
    if not findings:
        return 0.0
    top = max(findings, key=lambda f: _IMPACT_RANK.get((f.get("impact") or "").upper(), 0))
    return _IMPACT_SCORE.get((top.get("impact") or "").upper(), 0.0)


def get_elastic_auth():
    user = os.getenv("ELASTIC_USER", "elastic")
    pwd = os.getenv("ELASTIC_PASSWORD", "")
    if not pwd and Path(".env").exists():
        for line in Path(".env").read_text().splitlines():
            if line.startswith("ELASTIC_PASSWORD="):
                pwd = line.split("=", 1)[1].strip().strip('"').strip("'")
            if line.startswith("ELASTIC_USER="):
                user = line.split("=", 1)[1].strip().strip('"').strip("'")
    return (user, pwd)

def ship_to_elasticsearch(status_data):
    es_url = os.getenv("ELASTICSEARCH_URL", "http://127.0.0.1:9200/blockchain-soc-audit-logs/_doc")
    auth = get_elastic_auth()
    v104 = status_data.get("enterprise_v10_4", {})
    
    doc = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "pipeline_status": "COMPLETED",
        "contract": "VulnerableVault.sol",
        "dread_score": _compute_dread_score(),
        "gitleaks_leaks_count": v104.get("gitleaks", {}).get("findings_count", 0),
        "openscap_status": v104.get("openscap", {}).get("status", "PASS"),
        "avs_consensus": v104.get("avs_consensus", {}),
        "langgraph_swarm": v104.get("langgraph_swarm", {}),
        "vault_signature": v104.get("hashicorp_vault", {}).get("status", "ONLINE"),
        "jira_ticket": get_latest_jira_ticket()
    }

    try:
        res = requests.post(es_url, auth=auth, json=doc, headers={"Content-Type": "application/json"}, timeout=5)
        if res.status_code in [200, 201]:
            print(f"[+] [SIEM ELASTICSEARCH] Successfully indexed run document -> ID: {res.json().get('_id')}")
            return True
        else:
            print(f"[-] [SIEM ELASTICSEARCH] HTTP {res.status_code}: {res.text[:120]}")
            return False
    except Exception as e:
        print(f"[-] [SIEM ELASTICSEARCH] Connection failed: {e}")
        return False

def _read_json(rel):
    p = Path(rel)
    if p.is_file():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return None
    return None

def _tool_status_line(tool, endpoint, artifact, status_text, value):
    return (f'blockchain_soc_tool_status{{tool="{tool}",endpoint="{endpoint}",'
            f'artifact="{artifact}",status_text="{status_text}"}} {value}')

def _jira_tool_status_line():
    ticket_file = Path("reports/latest-jira-ticket.txt")
    if not ticket_file.is_file():
        return _tool_status_line("Atlassian Jira", "Cloud REST API", "no ticket produced this run", "NOT RUN", 0)
    key = ticket_file.read_text(encoding="utf-8").strip()
    local_artifact = Path(f"reports/jira-{key}.json")
    if local_artifact.is_file():
        return _tool_status_line("Atlassian Jira", "Cloud REST API", f"Incident ticket: {key}", "RECORDED LOCALLY (no live Jira dispatch)", 1)
    return _tool_status_line("Atlassian Jira", "Cloud REST API", f"Incident ticket: {key}", "DISPATCHED (live)", 1)

def export_prometheus_metrics(status_data, es_ok=False):
    v104 = status_data.get("enterprise_v10_4", {})
    avs = v104.get("avs_consensus", {})
    gl = v104.get("gitleaks", {})

    # Real per-run scanner results this run actually produced (reports/scanners/*.json),
    # never a fixed healthy default. A missing result file is itself a real signal
    # (that check didn't run this cycle), reported as not_run/0, not silently skipped.
    vault_res = _read_json("reports/scanners/vault-sign.json")
    sonar_res = _read_json("reports/scanners/sonar.json")
    jenkins_res = _read_json("reports/scanners/jenkins.json")
    swarm_res = _read_json("reports/scanners/swarm.json")
    avs_res = _read_json("reports/scanners/avs-consensus.json")
    trivy_res = _read_json("reports/scanners/trivy.json")
    dsomm_res = _read_json("reports/scanners/dsomm.json")
    k3s_res = _read_json("reports/scanners/k3s.json")

    def _ok(res):
        return 1 if (res and res.get("status") == "ok") else 0

    tool_status_lines = [
        _tool_status_line("HashiCorp Vault", "http://127.0.0.1:8200",
                           "Transit Key Attestation", (vault_res or {}).get("detail", "no result this run"),
                           _ok(vault_res)),
        _tool_status_line("SonarQube SAST", "http://127.0.0.1:9000",
                           f"gate={(sonar_res or {}).get('gate', 'unknown')}",
                           (sonar_res or {}).get("detail", "no result this run"), _ok(sonar_res)),
        _tool_status_line("Jenkins Enterprise", "http://127.0.0.1:8082",
                           "connectivity/auth check only",
                           (jenkins_res or {}).get("detail", "enterprise-integration step did not run this cycle"),
                           _ok(jenkins_res)),
        _jira_tool_status_line(),
        _tool_status_line("LangGraph Swarm", "192.168.0.189:11434",
                           f"decision={(swarm_res or {}).get('decision', 'unknown')}",
                           (swarm_res or {}).get("detail", "no result this run"), _ok(swarm_res)),
        _tool_status_line("Anvil AVS Consensus", ":8545, :8546, :8547",
                           f"final_verdict={(avs_res or {}).get('final_verdict', 'unknown')}",
                           (avs_res or {}).get("detail", "no result this run"),
                           (2 if (avs_res or {}).get("supermajority_exploit") else _ok(avs_res))),
        _tool_status_line("Elasticsearch SIEM", "http://127.0.0.1:9200",
                           "Index: blockchain-soc-audit-logs",
                           "indexed this run" if es_ok else "index failed this run",
                           1 if es_ok else 0),
        _tool_status_line("Kubernetes (K3s)", "local kubectl context",
                           f"node={(k3s_res or {}).get('target', 'unknown')} version={(k3s_res or {}).get('version', 'unknown')}",
                           (k3s_res or {}).get("detail", "no result this run"), _ok(k3s_res)),
    ]
    # Dropped rows with no real per-run check anywhere in this repo (Gnosis Safe's
    # pause-calldata build is printed but never persisted; Prometheus/Grafana's own
    # health, GitLab CE, and Argo CD have no live check wired into this pipeline) --
    # left out rather than defaulting them to "healthy".

    metrics = [
        "# HELP blockchain_soc_pipeline_success Pipeline execution status (1=success, 0=fail)",
        "# TYPE blockchain_soc_pipeline_success gauge",
        f"blockchain_soc_pipeline_success {1 if (status_data.get('pipeline', {}).get('health') == 'OK' and status_data.get('pipeline', {}).get('verdict') == 'PASS') else 0}",
        "# HELP blockchain_soc_gitleaks_findings Total secret leaks flagged",
        "# TYPE blockchain_soc_gitleaks_findings gauge",
        f"blockchain_soc_gitleaks_findings {gl.get('findings_count', 0)}",
        "# HELP blockchain_soc_trivy_vulns Real Trivy critical/high findings this run (0 if trivy did not run ok)",
        "# TYPE blockchain_soc_trivy_vulns gauge",
        f'blockchain_soc_trivy_vulns{{severity="critical"}} {(trivy_res or {}).get("counts", {}).get("critical", 0)}',
        f'blockchain_soc_trivy_vulns{{severity="high"}} {(trivy_res or {}).get("counts", {}).get("high", 0)}',
        "# HELP blockchain_soc_tool_status Multi-layer enterprise ecosystem status (1=OK/Active, 2=Halt/Tripped, 0=Down or no result this run)",
        "# TYPE blockchain_soc_tool_status gauge",
        *tool_status_lines,
        "# HELP blockchain_soc_bft_agreement_ratio Validator consensus ratio",
        "# TYPE blockchain_soc_bft_agreement_ratio gauge",
        f"blockchain_soc_bft_agreement_ratio {1.0 if avs.get('consensus_reached', True) else 0.0}",
        "# HELP blockchain_soc_dread_score Calculated DREAD risk score",
        "# TYPE blockchain_soc_dread_score gauge",
        f"blockchain_soc_dread_score {_compute_dread_score()}",
        "# HELP blockchain_soc_dsomm_activities_assessed_total OWASP DSOMM activities with real "
        "automated evidence this run (never a fixed level; most of DSOMM requires manual/"
        "organizational assessment no scanner can provide)",
        "# TYPE blockchain_soc_dsomm_activities_assessed_total gauge",
        f"blockchain_soc_dsomm_activities_assessed_total "
        f"{(dsomm_res or {}).get('counts', {}).get('activities_assessed', 0)}",
        "# HELP blockchain_soc_dsomm_activities_total Total activities in the official OWASP "
        "DSOMM model (denominator for the assessed-activities count, not a target to reach)",
        "# TYPE blockchain_soc_dsomm_activities_total gauge",
        f"blockchain_soc_dsomm_activities_total "
        f"{(dsomm_res or {}).get('counts', {}).get('activities_total', 0)}",
    ]
    for sub, data in (dsomm_res or {}).get("subdimensions", {}).items():
        sub_label = sub.replace('"', "")
        metrics.append(f'blockchain_soc_dsomm_level{{subdimension="{sub_label}"}} {data["level"]}')
        if data.get("coverage") is not None:
            metrics.append(f'blockchain_soc_dsomm_coverage_ratio{{subdimension="{sub_label}"}} {data["coverage"]}')

    for n in v104.get("langgraph_swarm", {}).get("nodes", []):
        agent_clean = n.get("agent", "unknown").replace(" ", "_").replace("(", "").replace(")", "")
        v_val = 1 if "HALT" in n.get("verdict", "") else 0
        metrics.append(f'blockchain_soc_agent_verdict{{agent="{agent_clean}"}} {v_val}')

    metrics_text = "\n".join(metrics) + "\n"
    out_file = Path("reports/metrics.prom")
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(metrics_text, encoding="utf-8")
    print(f"[+] [PROMETHEUS TELEMETRY] Prometheus metrics exported -> {out_file} ({len(metrics)} lines)")
    return metrics_text

class MetricsHTTPHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/metrics":
            m_path = Path("reports/metrics.prom")
            body = m_path.read_text(encoding="utf-8").encode("utf-8") if m_path.exists() else b""
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        return

def is_port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("127.0.0.1", port)) == 0

def ensure_metrics_server():
    if not is_port_in_use(9101):
        server = HTTPServer(("0.0.0.0", 9101), MetricsHTTPHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        print("[+] [PROMETHEUS LISTENER] Metrics endpoint listening on http://0.0.0.0:9101/metrics")
        # Keep open briefly to register
        threading.Event().wait(1.0)
    else:
        print("[*] [PROMETHEUS LISTENER] Port 9101 is already active and serving metrics.")

if __name__ == "__main__":
    s_path = Path("reports/status.json")
    if s_path.exists():
        data = json.loads(s_path.read_text(encoding="utf-8"))
        es_ok = ship_to_elasticsearch(data)
        export_prometheus_metrics(data, es_ok)
        ensure_metrics_server()
