# Local AVS Validator Quorum Simulation

## 1. Coursework & Educational Context
This cluster environment is an **educational coursework simulation** modeled on decentralized Actively Validated Services (AVS) within the EigenLayer / restaking ecosystem.

It is designed to run completely offline on local infrastructure without connecting to public blockchain testnets, external RPC providers, or real Ethereum mainnet validators.

## 2. Cluster Architecture
The topology provisions three independent validator nodes running inside isolated containerized runtimes:

| Validator ID | Container Name | Local Port | Network | Role |
| :--- | :--- | :--- | :--- | :--- |
| `validator-1` | `bsp_validator_1` | `8081` | `avs-validator-net` | Quorum Node 1 |
| `validator-2` | `bsp_validator_2` | `8082` | `avs-validator-net` | Quorum Node 2 |
| `validator-3` | `bsp_validator_3` | `8083` | `avs-validator-net` | Quorum Node 3 |

## 3. Communication & Consensus Protocol
- j*Endpoint `/health`**: Returns HTTP 200 indicating container readiness and node identity.
- j*Endpoint `/vote`**: Accepts a cryptographic finding attestation digest, executes local deterministic PoC Replay in an isolated sandbox, and emits a signed `ValidatorVote` payload.
- **Consensus Rule**: In accordance with Task P06-004, the `AVSGate` enforces a strict greater-than-66.7% (> 2/3) supermajority rule across all registered nodes before authorizing downstream incident response actions.

## 4. Operational Instructions
To launch the simulation cluster manually:
``@bash
docker compose -f docker/docker-compose.validators.yml up -d
```

To verify cluster health:
```bash
curl -s http://localhost:8081/health | jq .
curl -s http://localhost:8082/health | jq .
curl -s http://localhost:8083/health | jq .
```

To tear down the cluster:
```bash
compose -f docker/docker-compose.validators.yml down
```
