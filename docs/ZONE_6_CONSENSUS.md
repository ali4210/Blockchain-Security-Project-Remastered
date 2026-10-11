# Zone 6: Consensus Attack Detection & Gating Architecture

## 1. Executive Summary & Zero-Trust Architecture
Zone 6 provides real-time telemetry, threat detection, and mitigation gating for consensus-layer blockchain attacks. Operating within the project zero-trust security paradigm:
- Autonomous Agents (Agents B, E, G) have read-only, schema-validated, rate-limited access to analytical consensus telemetry tools via Model Context Protocol (MCP).
- Autonomous Agent Mutation Barrier: Agents are strictly prohibited by Open Policy Agent (OPA) policy from triggering mitigations, peer evictions, validator slashes, or gate overrides.
- Cryptographic Handoff: Actionable consensus findings of HIGH or CRITICAL severity must obtain a Byzantine Fault Tolerant (BFT) supermajority BLS QuorumCertificate (>66.7% validator signatures) before routing to Phase 9 mitigation pipelines.
- Operator Exclusivity: Active mitigation execution and manual gate overrides require authenticated human SOC operators presenting verified cryptographic credentials.

---

## 2. Threat Models & Attack Vectors

### 2.1 Chain Reorganization Attacks
- Mechanism: Adversary mines or produces an alternate block lineage in secret or takes advantage of high network latency to replace canonical blocks.
- Impact: Double spending, transaction reversion, and loss of deterministic finality.
- Severity Classifications:
  - MICRO_FORK (Depth = 1): Benign network latency or race condition.
  - DEEP_REORG (Depth 2 to 11): Heightened network partitioning or malicious private chain.
  - FINALITY_VIOLATION (Depth >= 12): Critical break of protocol finality rules.

### 2.2 Hashpower & Stake Concentration Cartels
- Mechanism: Consolidation of validation power into fewer than 3 dominant mining pools or staking liquid pools.
- Impact: Cartel censorship, MEV extraction monopolies, and unilateral chain manipulation.
- Mathematical Formulations:
  - Single Entity Dominance: s_max = max(s_i) where s_i is entity percentage share.
  - Top-3 Cartel Share: C_3 = sum(s_i for top 3).
  - Herfindahl-Hirschman Index (HHI): HHI = sum(s_i^2) where s_i is whole percentage points (0 to 10,000).

### 2.3 Statistical Selfish Mining
- Mechanism: Rogue pool withholds valid mined blocks, extending a private branch and publishing it strategically when the public chain approaches its length to invalidate honest work.
- Impact: Honest miner revenue suppression, difficulty adjustment manipulation, and heightened orphan rates.
- Statistical Model:
  - Orphan Rate Mean (mu) and Variance (sigma^2) calculated over a sliding window (N >= 10 blocks).
  - Standardized Orphan Score: z = (observed - mu) / sigma.
  - Strategic Branch Dump: Publication of private blocks inducing canonical chain reorg of depth >= 1.

### 2.4 P2P Eclipse Attacks
- Mechanism: Adversary populates target node peer routing table with attacker-controlled IP addresses.
- Impact: View isolation, selective mempool censorship, and vulnerability to zero-confirmation double spends.
- Evaluation Metrics:
  - Subnet Concentration: Monopolization of /24 IPv4 subnets (>50%).
  - Autonomous System Number (ASN) Diversity: Concentration of peer endpoints under a single ASN (>50%).

---

## 3. Mathematical Detector Thresholds

| Detector Module | Metric / Indicator | Warning Threshold | Critical Threshold | Action Required |
|---|---|---|---|---|
| ChainReorgMonitor | Reorg Depth (D) | 2 <= D < 12 (WARNING) | D >= 12 (CRITICAL) | Graph enrichment; AVS attestation for D >= 3 |
| ConsensusConcentrationTracker | Single Entity Share (s_max) | > 33.0% | > 51.0% | Network stability warning; AVS attestation for > 51% |
| ConsensusConcentrationTracker | Top-3 Cartel Share (C_3) | > 50.0% | > 66.7% | Egress barrier warning |
| ConsensusConcentrationTracker | Market HHI | > 1,800 (Concentrated) | > 2,500 (Highly Monopolized) | Enrichment; SOC escalation |
| SelfishMiningDetector | Orphan Rate z-score | z >= 3.0 | z >= 4.0 with Private Dump | Threat graph enrichment; rogue miner attribution |
| P2PEclipseDetector | Subnet / ASN Share | > 30.0% | > 50.0% | Alert enrichment; peer table re-randomization |

---

## 4. Model Context Protocol (MCP) Tool Contracts

The ConsensusMcpRegistry exposes 6 analytical inspection tools:
1. get_mempool_telemetry: Retrieves real-time mempool transaction metrics and propagation delay percentiles.
2. get_topology_summary: Returns connected peer count, subnet distribution, and ASN diversity metrics.
3. get_reorg_history: Queries recent chain reorganizations, micro-forks, and finality violations.
4. get_concentration_metrics: Returns top entity shares, cartel dominance, and HHI index values.
5. evaluate_selfish_mining: Evaluates orphan rate z-scores and private branch dump counts for a miner or pool.
6. evaluate_eclipse_status: Assesses peer table diversification and returns eclipse vulnerability alerts.

---

## 5. AVS Supermajority Quorum Rules & Cryptographic Proofs

Actionable findings with requires_avs: true are submitted to ConsensusAvsRouter and validated against exact integer BFT supermajority arithmetic:
3 * V > 2 * N

Where:
- V = Count of verified, non-duplicate validator signatures.
- N = Total registered validator set size.

Quorum Verification Invariants:
1. Finding Digest Binding: H_cert(finding_digest) == H_sha256(finding_payload).
2. Execution Receipt Binding: Message digest incorporates canonical or execution receipt hash:
   M = H_sha256(attestation_id + ":" + finding_digest + ":" + receipt_hash).
3. Replay Protection: attestation_id is recorded upon successful routing; duplicate submissions are rejected.
4. Aggregate Signature Verification: Validates aggregate hash bundle across registered validator keyring.

---

## 6. OPA Boundary Policy & Agent Integration

Role Matrix:
- Agent B (Hunter): ALLOW read/observe; DENY mitigate/override.
- Agent E (Barrier): ALLOW read/observe; DENY mitigate/override.
- Agent G (Remediation): ALLOW read/observe; DENY mitigate/override.
- Human Operator: ALLOW all actions (requires valid Ed25519 token).
- Compliance Officer: ALLOW read/observe; DENY mitigate/override.
- External / Unknown: DENY all actions.

Rate Limiting:
Each agent client (AgentConsensusClient) wraps queries in a Token Bucket rate limiter:
- Default Burst Capacity: 10 tokens.
- Refill Rate: 2.0 tokens/second.
- Behavior on Depletion: Raises RateLimitExceededError to prevent runaway polling loops.
