# Observability Network & Telemetry Architecture (Task P08-001)

## 1. Architectural Overview
The Blockchain SOC telemetry pipeline leverages real-time metrics, runtime application self-protection (RASP) on-chain traces, and structured forensic security logs.

The host environment runs both enterprise and lightweight stacks via Docker host networking (`--network host`):

| Component | Port | Network Mode | Active Service | Purpose |
|---|---|---|---|---|
| **Prometheus** | `9090` | host | `cross-prometheus` (v2.51.0) | Metric collection from agents, AVS, RASP (`:9100-9102`) |
| **Elasticsearch** | `9200` | host | `cross-elasticsearch` (v8.11.0) | Structured ECS JSON security logging (`blockchain-soc-logs-*`) |
| **Kibana** | `5601` | host | `cross-kibana` (v8.11.0) | Security dashboarding and log investigation |
| **Grafana** | `3000` | host | `cross-grafana` (v10.4.0) | Lightweight metric and trace visualization alternative |
| **Node Exporter** | `9100` | host | `cross-node-exporter` (v1.7.0) | System-level infrastructure metrics |

## 2. Authentication & Access Profiles

### Profile A: Full Enterprise (Prometheus + Elasticsearch/Kibana)
- **Metrics Endpoint**: `http://localhost:9090/metrics`
- **Log Index Pattern**: `blockchain-soc-logs-YYYY.MM.DD`
- **Elasticsearch Access**: HTTP Basic Auth or API Key tokens (HTTP 401 challenge verified).
- **Log Format**: Elastic Common Schema (ECS) v1.12+.

### Profile B: Lightweight Replacement (Prometheus + Grafana/Loki)
- **Metrics Endpoint**: `http://localhost:9090`
- **Dashboard Service**: `http://localhost:3000`
- **Low Footprint Mode**: Utilizes in-memory / lightweight log streaming when running restricted CI test environments.

## 3. Standard Metric Definitions
- `blockchain_soc_deploy_total`: Counter for contract deployment executions.
- `blockchain_soc_deploy_aborted_total`: Counter for fail-closed deployment aborts.
- `blockchain_soc_consensus_quorum_ratio`: Gauge measuring BLS validator agreement ratio.
- `blockchain_soc_rasp_suspicious_tx_total`: Counter for flagged malicious on-chain transactions.
- `blockchain_soc_rasp_active_monitors`: Gauge tracking active shadow-fork listeners.
