# Practical Tier 1 / Tier 2 Model Schedule for Swarm VRAM Lifecycle

## 1. Executive Summary & Hardware Envelope
The Phase 5 Autonomous Swarm Core executes automated blockchain security workflows across 7 specialized LLM agents (Agents A through G). Because multi-agent execution runs on local or private infrastructure with bounded GPU memory (24GB VRAM target envelope, e.g., NVIDIA RTX 3090/4090 or L40), loading multiple models simultaneously results in CUDA Out-Of-Memory (OOM) crashes or destructive context thrashing.

To ensure deterministic, stable execution:
1. **Single-Lane Sequential Pipeline**: Agents execute in a sequential topological chain.
2. **Ephemeral VRAM Lifecycle**: Between each stage, the loaded model is explicitly purged from GPU memory via `purge_model(keep_alive=0)`.
3. **Dual Tier Strategy**: The swarm provides Tier 1 (24GB target for full auditing accuracy) and Tier 2 (12–16GB fallback for local developer testing and constrained environments).

---

## 2. Model Schedule Matrix

| Agent | Specialized Function | Tier 1 Model (24GB VRAM) | Context (`num_ctx`) | Tier 2 Model (12–16GB VRAM) | Context (`num_ctx`) | Timeout Cap |
|---|---|---|---|---|---|---|
| **Agent A** | Smart Contract Auditor | `qwen2.5-coder:32b` (Q4_K_M) | 32,768 (32K) | `qwen2.5-coder:14b` (Q4_K_M) | 16,384 (16K) | 180s |
| **Agent B** | SIEM Threat Hunter | `deepseek-r1:32b` (Q4_K_M) | 16,384 (16K) | `deepseek-r1:14b` (Q4_K_M) | 8,192 (8K) | 180s |
| **Agent C** | Compliance Judge | `qwen2.5:32b` (Q4_K_M) | 8,192 (8K) | `qwen2.5:14b` (Q4_K_M) | 8,192 (8K) | 180s |
| **Agent D** | Red Teamer / Exploit Gen | `deepseek-r1:32b` (Q4_K_M) | 16,384 (16K) | `deepseek-r1:14b` (Q4_K_M) | 8,192 (8K) | 180s |
| **Agent E** | Incident Commander | `qwen2.5:32b` (Q4_K_M) | 8,192 (8K) | `qwen2.5:14b` (Q4_K_M) | 8,192 (8K) | 180s |
| **Agent F** | Deep Logic Analyzer | `deepseek-r1:32b` (Q4_K_M) | 32,768 (32K) | `deepseek-r1:14b` (Q4_K_M) | 16,384 (16K) | 180s |
| **Agent G** | Guardrail Watchdog | `qwen2.5-coder:32b` (Q4_K_M) | 32,768 (32K) | `qwen2.5-coder:7b` (Q4_K_M) | 16,384 (16K) | 300s (Capped) |

---

## 3. VRAM Allocation Breakdown

### Tier 1 Profile (24GB VRAM Envelope)
- **Model Weights (Q4_K_M 32B)**: ~19.2 GB VRAM.
- **KV Cache Overhead (FP16 / FlashAttention)**:
  - 8K context: ~1.0 GB VRAM.
  - 16K context: ~2.0 GB VRAM.
  - 32K context: ~3.8 GB VRAM.
- **Peak Memory Utilization**: ~23.0 GB VRAM (Fits inside 24GB buffer with ~1GB safety headroom).

### Tier 2 Profile (12–16GB VRAM Envelope)
- **Model Weights (Q4_K_M 14B)**: ~8.8 GB VRAM.
- **KV Cache Overhead (FP16 / FlashAttention)**:
  - 8K context: ~0.6 GB VRAM.
  - 16K context: ~1.2 GB VRAM.
- **Peak Memory Utilization**: ~10.0 GB – 11.2 GB VRAM (Operates cleanly within 12GB–16GB VRAM).

---

## 4. Lifecycle Enforcement & Guardrails
1. **Agent G 300s Timeout Cap**: Agent G enforces sanitization and integrity checks. It is strictly bounded by a 300.0s deterministic timeout ceiling (`AGENT_TIMEOUTS["G"] = 300.0`).
2. **Deterministic Purge Calls**: When an agent finishes its pipeline turn, `src/llm_client/ollama_client.py:agent_stage()` calls `purge_model(model)` issuing an HTTP POST to Ollama `/api/generate` with `keep_alive: 0`.
3. **Empty Model Registry Assertion**: Between stages, `/api/ps` must report zero models resident before the next model is loaded.
