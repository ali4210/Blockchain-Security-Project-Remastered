#!/usr/bin/env python3
import os
import json
import requests

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATUS_FILE = os.path.join(PROJECT_ROOT, "reports", "status.json")
PROM_FILE = os.path.join(PROJECT_ROOT, "reports", "metrics.prom")

VAULT_ADDR = os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
VAULT_TOKEN = os.environ.get("VAULT_TOKEN")
URL = os.environ.get("DEFECTDOJO_URL", "http://127.0.0.1:8085") + "/api/v2"

# Token: env var first, else Vault secret/data/defectdojo (needs VAULT_TOKEN).
# Never hardcoded, never read from a tracked file.
TOKEN = os.environ.get("DEFECTDOJO_TOKEN")
if not TOKEN and VAULT_TOKEN:
    try:
        resp = requests.get(
            f"{VAULT_ADDR}/v1/secret/data/defectdojo",
            headers={"X-Vault-Token": VAULT_TOKEN}, timeout=5,
        )
        data = resp.json().get("data", {}).get("data", {})
        TOKEN = data.get("token")
        URL = data.get("url", URL.replace("/api/v2", "")) + "/api/v2"
    except Exception:
        TOKEN = None

if not TOKEN:
    print("[*] [DEFECTDOJO EXPORTER] No DEFECTDOJO_TOKEN (env or Vault secret/data/defectdojo); skipping")
    raise SystemExit(0)

HEADERS = {"Authorization": f"Token {TOKEN}"}


def fetch_metrics():
    try:
        # 1. DefectDojo Queries
        all_resp = requests.get(f"{URL}/findings/?limit=1", headers=HEADERS, timeout=5)
        active_resp = requests.get(f"{URL}/findings/?active=true&duplicate=false&limit=500", headers=HEADERS, timeout=5)
        defectdojo_ok = all_resp.status_code == 200 and active_resp.status_code == 200
        all_res = all_resp.json() if defectdojo_ok else {}
        active_res = active_resp.json() if defectdojo_ok else {}

        # Query specific ZAP Test ID to isolate true DAST alerts count.
        # No hardcoded fallback: if the query fails or finds nothing, report 0 and say so
        # rather than silently reporting a fixed invented number.
        zap_test_res = requests.get(f"{URL}/tests/?engagement__name=SOC-Continuous-Compliance&test_type__name=ZAP+Scan", headers=HEADERS, timeout=5).json()
        zap_alerts = 0
        zap_source = "no ZAP test found in DefectDojo"
        zap_ok = zap_test_res.get("count", 0) > 0
        if zap_ok:
            last_zap_id = zap_test_res["results"][-1]["id"]
            zap_alerts_res = requests.get(f"{URL}/findings/?test={last_zap_id}", headers=HEADERS, timeout=5).json()
            zap_alerts = zap_alerts_res.get("count", 0)
            zap_source = f"queried from DefectDojo test id {last_zap_id}"

        # TheHive case count: query TheHive itself for real, instead of a hardcoded constant.
        thehive_cases = None
        thehive_url = os.environ.get("THEHIVE_URL", "http://127.0.0.1:9005")
        thehive_token = os.environ.get("THEHIVE_TOKEN")
        if thehive_token:
            try:
                th_res = requests.post(
                    f"{thehive_url}/api/v1/query",
                    headers={"Authorization": f"Bearer {thehive_token}"},
                    json={"query": [{"_name": "listCase"}, {"_name": "count"}]},
                    timeout=5,
                ).json()
                thehive_cases = th_res if isinstance(th_res, int) else th_res.get("count")
            except Exception:
                thehive_cases = None
        thehive_status_text = "HEALTHY (Active)" if thehive_cases is not None else "UNKNOWN (no THEHIVE_TOKEN or query failed)"
        thehive_cases_line = thehive_cases if thehive_cases is not None else 0

        total_raw = all_res.get("count", 0)
        total_unique = active_res.get("count", 0)

        severities = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in active_res.get("results", []):
            sev = f.get("severity", "Info")
            severities[sev] = severities.get(sev, 0) + 1

        # 2. Update status.json
        if os.path.exists(STATUS_FILE):
            with open(STATUS_FILE, "r") as fp:
                data = json.load(fp)
            data["defectdojo_compliance"] = {
                "status": "HEALTHY",
                "dashboard_url": URL.replace("/api/v2", ""),
                "total_raw_findings": total_raw,
                "active_unique_findings": total_unique,
                "severity_breakdown": severities,
                "zap_alerts_source": zap_source,
            }
            with open(STATUS_FILE, "w") as fp:
                json.dump(data, fp, indent=2)

        # 3. Append to Prometheus metrics.prom for Grafana Port 3000
        prom_lines = [
            "\n# HELP defectdojo_active_unique_findings Number of active deduplicated findings in DefectDojo",
            "# TYPE defectdojo_active_unique_findings gauge",
            f"defectdojo_active_unique_findings {total_unique}",
            "# HELP defectdojo_raw_total_findings Total raw findings uploaded to DefectDojo",
            "# TYPE defectdojo_raw_total_findings gauge",
            f"defectdojo_raw_total_findings {total_raw}",
            "# HELP defectdojo_findings_by_severity Active findings grouped by severity",
            "# TYPE defectdojo_findings_by_severity gauge",
            f'defectdojo_findings_by_severity{{severity="Critical"}} {severities.get("Critical", 0)}',
            f'defectdojo_findings_by_severity{{severity="High"}} {severities.get("High", 0)}',
            f'defectdojo_findings_by_severity{{severity="Medium"}} {severities.get("Medium", 0)}',
            f'defectdojo_findings_by_severity{{severity="Low"}} {severities.get("Low", 0)}',
            "# HELP zap_dast_alerts_total Total DAST alerts cataloged from OWASP ZAP",
            "# TYPE zap_dast_alerts_total gauge",
            f"zap_dast_alerts_total {zap_alerts}",
            "# HELP thehive_cases_total Total forensic incident cases managed in TheHive",
            "# TYPE thehive_cases_total gauge",
            f"thehive_cases_total {thehive_cases_line}",
            f'blockchain_soc_tool_status{{tool="DefectDojo Compliance",endpoint="{URL.replace("/api/v2", "")}",artifact="Continuous AppSec Hub & Ingestion Engine",status_text="{"HEALTHY (Active)" if defectdojo_ok else "UNREACHABLE / QUERY FAILED"}"}} {1 if defectdojo_ok else 0}',
            f'blockchain_soc_tool_status{{tool="TheHive 4 SIEM",endpoint="{thehive_url}",artifact="Incident Response & Case Management",status_text="{thehive_status_text}"}} {1 if thehive_cases is not None else 0}',
            f'blockchain_soc_tool_status{{tool="OWASP ZAP DAST",endpoint="Containerized (Host Net)",artifact="Dynamic Baseline AppSec Scan",status_text="{zap_source}"}} {1 if zap_ok else 0}\n'
        ]

        if os.path.exists(PROM_FILE):
            with open(PROM_FILE, "a") as pf:
                pf.write("\n".join(prom_lines))
            print(f"[+] [PROMETHEUS] Exported DefectDojo ({total_unique} flaws), ZAP DAST ({zap_alerts} alerts, {zap_source}), and TheHive ({thehive_cases_line} cases) to {PROM_FILE}")
    except Exception as exc:
        print(f"[*] [DEFECTDOJO EXPORTER] Error: {exc}")


if __name__ == "__main__":
    fetch_metrics()