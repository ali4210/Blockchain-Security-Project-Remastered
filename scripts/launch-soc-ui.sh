#!/usr/bin/env bash
# ==============================================================================
# Autonomous Blockchain SOC — Master Web Console Launcher
# Opens all 12 pipeline tools + Executive Dashboard in Firefox tabs.
# ==============================================================================

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Check if firefox is installed
if ! command -v firefox &>/dev/null; then
    echo "[-] Error: Firefox is not installed or not in PATH."
    exit 1
fi

echo "=================================================================="
echo "  LAUNCHING ALL 12 ENTERPRISE BLOCKCHAIN SOC CONSOLES"
echo "=================================================================="

# Complete array of all 12 integrated tools + local executive report
URLS=(
    "http://localhost:8200/ui"                               # 1. HashiCorp Vault
    "http://localhost:8929"                                  # 2. GitLab CE
    "http://localhost:8080"                                  # 3. Argo CD GitOps
    "http://localhost:9090"                                  # 4. Prometheus Server
    "http://localhost:9200"                                  # 5. Elasticsearch Engine
    "http://localhost:5601"                                  # 6. Kibana SIEM Dashboard
    "http://localhost:3000"                                  # 7. Grafana Metrics
    "http://localhost:8082"                                  # 8. Jenkins CI/CD
    "http://localhost:9000"                                  # 9. SonarQube SAST Gate
    "http://localhost:8085"                                  # 10. DefectDojo Compliance Hub
    "http://localhost:9005"                                  # 11. TheHive 4 SOAR
    "http://localhost:3100"                                  # 12. Langfuse Observability
    "file://${PROJECT_DIR}/reports/latest.html"              # Executive Summary Report
)

TOOL_NAMES=(
    "HashiCorp Vault (:8200)"
    "GitLab CE (:8929)"
    "Argo CD GitOps (:8080)"
    "Prometheus (:9090)"
    "Elasticsearch SIEM (:9200)"
    "Kibana SIEM Visualizer (:5601)"
    "Grafana Dashboard (:3000)"
    "Jenkins CI/CD (:8082)"
    "SonarQube SAST (:9000)"
    "DefectDojo Hub (:8085)"
    "TheHive 4 SOAR (:9005)"
    "Langfuse Observability (:3100)"
    "Executive SOC Report (latest.html)"
)

for i in "${!URLS[@]}"; do
    printf "  [+] %-2d. %-35s -> %s\n" "$((i+1))" "${TOOL_NAMES[$i]}" "${URLS[$i]}"
done

# Launch all URLs into new tabs in Firefox
firefox --new-tab "${URLS[@]}" &>/dev/null &

echo "=================================================================="
echo "[+] All 12 tools + Executive Report dispatched to Firefox tabs."
echo "=================================================================="
