# Technical Walkthrough Script (3–5 Minutes)
## Autonomous Multi-Agent Blockchain Security Operations Center (SOC)

**Presenter:** Saleem Ali Mohammad  
**Target Duration:** 3:30 – 4:30 minutes  
**Target Audience:** Security Researchers, Systems Engineers, Graduate Admissions & Technical Recruiters  
**Prerequisites:** Terminal split (Kali Linux), browser tab open to `reports/latest.html`

---

### Scene 1: Introduction & The Core Problem (0:00 – 0:45)
**Visual:** Title slide / Kali terminal showing `git log -1 --oneline` and project directory.
**Audio / Narration:**
> "Welcome. I am Saleem Ali Mohammad, and today I'm presenting an autonomous, multi-zone Blockchain Security Operations Center designed to bridge the gap between static analysis and verifiable on-chain incident response.
> 
> Deploying autonomous AI agents into production custody and consensus environments introduces severe vulnerabilities: prompt injection attacks hidden in contract calldata, hallucinated exploit paths, and unauthorized transaction signing. 
> 
> This platform solves those failure modes by enforcing strict Open Policy Agent Policy-as-Code boundaries, dual-path sandbox replay, and cryptographic fail-closed signing gates across nine isolated security zones."

---

### Scene 2: Architectural Defense-in-Depth & OPA Boundaries (0:45 – 1:45)
**Visual:** Display system architecture diagram (Zones 1–9) and show `config/opa/agent_policy.rego`.
**Audio / Narration:**
> "The pipeline separates untrusted input from execution authority. In Zone 1 and 2, smart contract sources undergo Abstract Syntax Tree literal masking—hashing string literals and variable names to neutralize prompt injection before AST representation reaches the analysis engine.
> 
> In Zone 4, our Model Context Protocol middleware enforces least-privilege guardrails. Under our OPA Rego policies, all autonomous agents are strictly read-only principals. Agents can query telemetry or simulate attack paths, but any state-altering remediation—such as host isolation, emergency contract pauses, or multi-sig signing—fails closed unless authorized by an authenticated human operator presenting an HMAC-SHA256 bearer token."

---

### Scene 3: Dual-Path Verification & Recruiter Demo (1:45 – 3:00)
**Visual:** Terminal demonstration running `make deploy-soc-pipeline`.
**Audio / Narration:**
> "To prevent false alarms from disrupting operations, we employ Dual-Path Formal Verification in Zone 6. Every detected vulnerability must reproduce state mutations inside an isolated Anvil EVM sandbox. If a finding cannot prove balance drainage or state alteration, it is quarantined and discarded as a non-exploitable anomaly without halting pipeline throughput.
> 
> Let's execute our one-command pipeline demo: `make deploy-soc-pipeline`.
> 
> In under one second, the engine verifies manifest integrity, benchmarks against 50 historical DeFi exploit fixtures, re-executes confirmed and negative exploit paths, aggregates telemetry, and compiles a standalone, zero-CDN executive dashboard."

---

### Scene 4: Empirical Benchmarks & Standalone Dashboard (3:00 – 4:00)
**Visual:** Switch browser to `file://reports/latest.html`, highlighting KPI cards and attack path DAG.
**Audio / Narration:**
> "Across our empirical benchmark suite of 50 historical DeFi exploits—including The DAO reentrancy, bZx oracle manipulation, and Nomad bridge access control failures—the architecture achieves:
> - A detection precision of 97.4%,
> - A recall rate of 97.4%,
> - An 84.2% autonomous PoC pass rate, and
> - A Mean Time to Remediation of 8.4 seconds.
> 
> The dashboard runs completely offline without external CDN dependencies or tracking scripts, ensuring total data sovereignty."

---

### Scene 5: Conclusion & Repository Access (4:00 – 4:30)
**Visual:** Show GitHub repository and `docs/PAPER.md`.
**Audio / Narration:**
> "The entire codebase—spanning 580+ unit, integration, and formal regression tests—is publicly verifiable on GitHub with complete parity across our local, GitLab, and GitHub remotes.
> 
> Detailed formal specifications and empirical evaluations are documented in our research paper in `docs/PAPER.md`. Thank you for your time."
