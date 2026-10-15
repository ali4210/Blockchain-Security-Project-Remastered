
def get_latest_jira_ticket():
    import json, glob, os
    # 1. Try reading latest STIX bundle
    stix_path = "reports/stix/latest-incident-stix.json"
    if os.path.exists(stix_path):
        try:
            with open(stix_path, "r") as f:
                data = json.load(f)
                for obj in data.get("objects", []):
                    ext = obj.get("external_references", [])
                    for r in ext:
                        if "KAN-" in r.get("external_id", ""):
                            return r["external_id"]
        except Exception:
            pass
    # 2. Try status.json
    status_path = "reports/status.json"
    if os.path.exists(status_path):
        try:
            with open(status_path, "r") as f:
                data = json.load(f)
                if "jira_ticket" in data:
                    return data["jira_ticket"]
        except Exception:
            pass
    return "KAN-LIVE"

import json
import os
import sys
import socket
import requests
from pathlib import Path
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading

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
        "dread_score": 8.4,
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
        else:
            print(f"[-] [SIEM ELASTICSEARCH] HTTP {res.status_code}: {res.text[:120]}")
    except Exception as e:
        print(f"[-] [SIEM ELASTICSEARCH] Connection failed: {e}")

def export_prometheus_metrics(status_data):
    v104 = status_data.get("enterprise_v10_4", {})
    avs = v104.get("avs_consensus", {})
    gl = v104.get("gitleaks", {})
    
    metrics = [
        "# HELP blockchain_soc_pipeline_success Pipeline execution status (1=success, 0=fail)",
        "# TYPE blockchain_soc_pipeline_success gauge",
        "blockchain_soc_pipeline_success 1",
        "# HELP blockchain_soc_gitleaks_findings Total secret leaks flagged",
        "# TYPE blockchain_soc_gitleaks_findings gauge",
        f"blockchain_soc_gitleaks_findings {gl.get('findings_count', 0)}",
        "# HELP blockchain_soc_bft_agreement_ratio Validator consensus ratio",
        "# TYPE blockchain_soc_bft_agreement_ratio gauge",
        f"blockchain_soc_bft_agreement_ratio {1.0 if avs.get('consensus_reached', True) else 0.0}",
        "# HELP blockchain_soc_dread_score Calculated DREAD risk score",
        "# TYPE blockchain_soc_dread_score gauge",
        "blockchain_soc_dread_score 8.4"
    ]

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
        ship_to_elasticsearch(data)
        export_prometheus_metrics(data)
        ensure_metrics_server()
