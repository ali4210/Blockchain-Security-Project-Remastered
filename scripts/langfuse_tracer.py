#!/usr/bin/env python3
import os
import requests
import json
import uuid
from datetime import datetime, timezone

class LangfuseSOCBridge:
    def __init__(self, env_path="config/.langfuse.env"):
        self.enabled = False
        self.env = {}
        if os.path.exists(env_path):
            with open(env_path) as f:
                for line in f:
                    if "=" in line and not line.startswith("#"):
                        k, v = line.strip().split("=", 1)
                        self.env[k] = v.strip('"\'')
            self.pk = self.env.get("LANGFUSE_PUBLIC_KEY")
            self.sk = self.env.get("LANGFUSE_SECRET_KEY")
            self.host = self.env.get("LANGFUSE_HOST", "http://127.0.0.1:3100")
            if self.pk and self.sk:
                self.enabled = True

    def record_agent_decision(self, trace_name, agent_name, model_name, prompt_in, verdict_out, metadata=None):
        if not self.enabled:
            return None
        now = datetime.now(timezone.utc).isoformat()
        trace_id = str(uuid.uuid4())
        obs_id = str(uuid.uuid4())
        payload = {
            "batch": [
                {
                    "id": str(uuid.uuid4()),
                    "type": "trace-create",
                    "timestamp": now,
                    "body": {
                        "id": trace_id,
                        "name": trace_name,
                        "input": prompt_in,
                        "output": verdict_out,
                        "metadata": metadata or {},
                        "tags": ["Autonomous-SOC", "Multi-Agent-Swarm"]
                    }
                },
                {
                    "id": str(uuid.uuid4()),
                    "type": "generation-create",
                    "timestamp": now,
                    "body": {
                        "id": obs_id,
                        "traceId": trace_id,
                        "name": agent_name,
                        "model": model_name,
                        "input": prompt_in,
                        "output": verdict_out,
                        "startTime": now,
                        "endTime": now
                    }
                }
            ]
        }
        try:
            res = requests.post(
                f"{self.host}/api/public/ingestion",
                auth=(self.pk, self.sk),
                headers={"Content-Type": "application/json"},
                data=json.dumps(payload),
                timeout=3
            )
            return res.status_code in [200, 201, 207]
        except Exception:
            return False

if __name__ == "__main__":
    bridge = LangfuseSOCBridge()
    ok = bridge.record_agent_decision(
        "Autonomous-SOC-Pipeline-Run",
        "Agent_D_Red_Teamer",
        "qwen2.5-coder:32b",
        "Analyze reentrancy state graph in VulnerableVault.sol",
        "HALT_CONFIRMED: Exploit sequence confirmed via Anvil BFT fork.",
        {"severity": "CRITICAL", "cwe": "CWE-841"}
    )
    print(f"[+] Langfuse SOC Bridge test result: {ok}")
