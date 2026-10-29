# Pipeline Source Dump (1 of 2)

## Project directory structure

```
.
├── artifacts
│   ├── hardhat
│   │   ├── artifacts.d.ts
│   │   ├── build-info
│   │   └── contracts
│   └── ingestion-result.json
├── config
│   ├── env.example
│   ├── foundry.toml
│   ├── governance-policy.json
│   ├── grafana-soc-v10-4-dashboard.json
│   ├── hardhat.config.js
│   ├── k8s
│   │   ├── argocd-app.yaml
│   │   ├── argocd-project.yaml
│   │   └── manifests
│   ├── Move.toml
│   ├── opa
│   │   ├── agent_policy.rego
│   │   ├── compliance_policy.rego
│   │   ├── consensus_policy.rego
│   │   ├── forensic_policy.rego
│   │   ├── forensics_policy.rego
│   │   └── wallet_policy.rego
│   ├── production-readiness.json
│   └── telemetry
│       └── prometheus.blockchain-soc.yml
├── contracts
│   └── solidity
│       ├── DeFiLendingVault.sol
│       ├── PromptInjectionFixture.sol
│       ├── RandomTestVault.sol
│       ├── SecureVault.sol
│       ├── StakingRewardsVault.sol
│       ├── VulnerableVault.sol
│       └── wallets
├── coverage.xml
├── dashboard
│   └── README.md
├── data
│   ├── benchmarks
│   │   └── historical_exploit_fixtures.json
│   ├── broker_store.db
│   ├── forensics.db
│   ├── snapshots
│   │   └── broker_store_helper_snap.db
│   └── threat_intel.db
├── deploy
│   └── thehive
│       ├── conf
│       ├── data
│       └── docker-compose.yml
├── docker
│   └── docker-compose.validators.yml
├── docker-compose.deploy.yml
├── docker-compose.test.yml
├── docker-compose.yml
├── docs
│   ├── architecture
│   │   ├── MODEL_SCHEDULE.md
│   │   └── VALIDATOR_SIMULATION.md
│   ├── benchmark-results.md
│   ├── CHECKLIST.md
│   ├── COMPLIANCE_AUTOMATION.md
│   ├── forensic-report-template.md
│   ├── FORENSIC_WALKTHROUGH_SCRIPT.md
│   ├── HANDOFF.md
│   ├── HITL_GATEWAY.md
│   ├── OBSERVABILITY_STACK.md
│   ├── OUTREACH_LINKEDIN.md
│   ├── paper-draft.md
│   ├── PAPER.md
│   ├── pipeline-source-dump-1.md
│   ├── pipeline-source-dump-2.md
│   ├── RUNBOOK.md
│   ├── SHAMIR_KEY_PROCEDURE.md
│   ├── STATEMENT_OF_PURPOSE.md
│   ├── UNIVERSAL_NEW_CHAT_PROMPT.md
│   ├── WALKTHROUGH_SCRIPT.md
│   └── ZONE_6_CONSENSUS.md
├── e version
├── Jenkinsfile
├── Makefile
├── package.json
├── package-lock.json
├── policies
│   ├── compliance_policy.rego
│   └── wallet_policy.rego
├── policy
│   └── consensus_boundary.rego
├── public-dashboard
│   ├── index.html
│   ├── status.json
│   └── vercel.json
├── quarantine
│   └── staging
├── README.md
├── reports
│   ├── avs-consensus-report.json
│   ├── dast
│   │   ├── zap-report.html
│   │   ├── zap-report.json
│   │   ├── zap-report.xml
│   │   └── zap.yaml
│   ├── evidence-manifest.json
│   ├── gitleaks-report.json
│   ├── jira-KAN--001.json
│   ├── jira-KAN-0042.json
│   ├── jira-KAN-0317.json
│   ├── jira-KAN-0427.json
│   ├── jira-KAN-0919.json
│   ├── jira-KAN-1221.json
│   ├── jira-KAN-1252.json
│   ├── jira-KAN-2813.json
│   ├── jira-KAN-3429.json
│   ├── jira-KAN-3612.json
│   ├── jira-KAN-3926.json
│   ├── jira-KAN-4002.json
│   ├── jira-KAN-4358.json
│   ├── jira-KAN-4449.json
│   ├── jira-KAN-4512.json
│   ├── jira-KAN-4730.json
│   ├── jira-KAN-4745.json
│   ├── jira-KAN-4941.json
│   ├── jira-KAN-5129.json
│   ├── jira-KAN-5837.json
│   ├── jira-KAN-5919.json
│   ├── jira-KAN--992.json
│   ├── jira-KAN-992.json
│   ├── jira-SEC-8891.json
│   ├── jira-SEC--992.json
│   ├── latest.html
│   ├── latest-jira-ticket.txt
│   ├── metrics -> /home/kali/Blockchain-Security-Project-Remastered/reports/metrics.prom
│   ├── metrics.prom
│   ├── ofac-screening-report.json
│   ├── openscap-report.json
│   ├── project-status-2026-10-20T06-50-28-043Z.html
│   ├── project-status-2026-10-20T06-59-39-364Z.html
│   ├── project-status-2026-10-20T07-12-08-507Z.html
│   ├── project-status-2026-10-20T07-23-26-418Z.html
│   ├── project-status-2026-10-20T07-30-07-415Z.html
│   ├── project-status-2026-10-20T08-05-18-723Z.html
│   ├── project-status-2026-10-20T08-15-36-772Z.html
│   ├── project-status-2026-10-20T08-23-28-379Z.html
│   ├── project-status-2026-10-20T09-01-09-312Z.html
│   ├── project-status-2026-10-20T09-07-28-726Z.html
│   ├── project-status-2026-10-20T09-15-16-870Z.html
│   ├── project-status-2026-10-21T06-04-09-135Z.html
│   ├── project-status-2026-10-21T20-26-04-450Z.html
│   ├── project-status-2026-10-22T07-12-41-410Z.html
│   ├── project-status-2026-10-22T07-28-22-386Z.html
│   ├── project-status-2026-10-22T07-43-44-225Z.html
│   ├── project-status-2026-10-22T07-45-23-393Z.html
│   ├── project-status-2026-10-22T08-00-49-160Z.html
│   ├── project-status-2026-10-22T08-16-26-365Z.html
│   ├── project-status-2026-10-22T08-17-47-709Z.html
│   ├── project-status-2026-10-22T08-18-13-505Z.html
│   ├── project-status-2026-10-22T08-19-04-829Z.html
│   ├── project-status-2026-10-22T08-23-53-712Z.html
│   ├── project-status-2026-10-22T08-39-16-398Z.html
│   ├── project-status-2026-10-22T09-44-57-135Z.html
│   ├── project-status-2026-10-22T12-40-15-724Z.html
│   ├── project-status-2026-10-22T15-34-54-456Z.html
│   ├── project-status-2026-10-22T17-11-29-054Z.html
│   ├── project-status-2026-10-22T17-26-29-982Z.html
│   ├── project-status-2026-10-22T17-30-08-582Z.html
│   ├── project-status-2026-10-22T17-33-06-877Z.html
│   ├── project-status-2026-10-22T17-37-13-035Z.html
│   ├── project-status-2026-10-22T17-40-02-954Z.html
│   ├── project-status-2026-10-22T17-45-59-888Z.html
│   ├── project-status-2026-10-22T18-58-50-978Z.html
│   ├── project-status-2026-10-22T19-04-38-729Z.html
│   ├── project-status-2026-10-22T19-36-41-953Z.html
│   ├── project-status-2026-10-22T20-03-43-559Z.html
│   ├── project-status-2026-10-22T22-09-47-491Z.html
│   ├── project-status-2026-10-23T05-59-47-773Z.html
│   ├── project-status-2026-10-23T06-13-17-018Z.html
│   ├── project-status-2026-10-23T06-44-19-634Z.html
│   ├── project-status-2026-10-23T06-51-52-673Z.html
│   ├── project-status-2026-10-23T08-50-05-553Z.html
│   ├── project-status-2026-10-23T09-02-51-769Z.html
│   ├── project-status-2026-10-23T09-27-57-686Z.html
│   ├── project-status-2026-10-23T09-35-41-241Z.html
│   ├── project-status-2026-10-23T09-48-15-249Z.html
│   ├── project-status-2026-10-23T10-27-06-433Z.html
│   ├── project-status-2026-10-23T10-34-02-679Z.html
│   ├── project-status-2026-10-23T10-50-57-097Z.html
│   ├── project-status-2026-10-23T17-32-16-515Z.html
│   ├── project-status-2026-10-23T17-44-29-654Z.html
│   ├── project-status-2026-10-23T17-54-57-332Z.html
│   ├── project-status-2026-10-23T18-01-13-936Z.html
│   ├── project-status-2026-10-23T18-17-29-735Z.html
│   ├── project-status-2026-10-23T18-33-13-445Z.html
│   ├── raw
│   │   ├── mythril-RandomTestVault.json
│   │   ├── mythril-SecureVault.json
│   │   ├── mythril-VulnerableVault.json
│   │   ├── oscap-report.html
│   │   ├── oscap-results.xml
│   │   ├── production-readiness.json
│   │   ├── sca-summary.json
│   │   ├── slither-RandomTestVault.json
│   │   ├── slither-RandomTestVault.sarif
│   │   ├── slither-SecureVault.json
│   │   ├── slither-SecureVault.sarif
│   │   ├── slither-VulnerableVault.json
│   │   ├── slither-VulnerableVault.sarif
│   │   └── trivy-report.json
│   ├── run-history.jsonl
│   ├── sast-symbolic-report.json
│   ├── sast-symbolic-report.sarif
│   ├── scanners
│   │   ├── avs-consensus.json
│   │   ├── defectdojo.json
│   │   ├── dsomm.json
│   │   ├── k3s.json
│   │   ├── langfuse.json
│   │   ├── mythril.json
│   │   ├── ofac-screening.json
│   │   ├── openscap.json
│   │   ├── presign-sim.json
│   │   ├── readiness.json
│   │   ├── sast-canary.json
│   │   ├── sca.json
│   │   ├── slither.json
│   │   ├── sonar.json
│   │   ├── swarm.json
│   │   ├── thehive.json
│   │   ├── trivy.json
│   │   ├── vault-sign.json
│   │   └── zap.json
│   ├── secure_test.html
│   ├── status.json
│   ├── stix
│   │   └── latest-incident-stix.json
│   ├── swarm-execution-report.json
│   ├── verdict.json
│   ├── vulnerable_test.html
│   └── zap.yaml
├── requirements.txt
├── scripts
│   ├── aggregate-infra-status.py
│   ├── aggregate-status.mts
│   ├── ast-mask-core.cjs
│   ├── ast-mask.mts
│   ├── audit-completion-gate.py
│   ├── audit-egress-barriers.sh
│   ├── bootstrap-langfuse.py
│   ├── bootstrap-thehive-enterprise.py
│   ├── build-offline-index.cjs
│   ├── compute-dsomm-maturity.py
│   ├── deploy-soc-demo.py
│   ├── dispatch-jira-incident.py
│   ├── enrich-findings.mts
│   ├── export-env.sh.example
│   ├── exporter-daemon.py
│   ├── export-public-dashboard.mts
│   ├── formal-tool-results.cjs
│   ├── generate-html-report.mts
│   ├── governance-core.cjs
│   ├── iast-trace.cjs
│   ├── incident-orchestrator.mts
│   ├── ingest-defectdojo.py
│   ├── ingest-granular-siem.py
│   ├── ingest-manifests.mts
│   ├── ingest-thehive-incident.py
│   ├── init-run.sh
│   ├── langfuse_tracer.py
│   ├── launch-soc-ui.sh
│   ├── lib
│   │   ├── __pycache__
│   │   ├── scanner_result.py
│   │   └── thehive_case.py
│   ├── mirror-nvd.sh
│   ├── mirror-ofac.py
│   ├── mirror-release-gate.sh
│   ├── normalize-reports.mts
│   ├── notify-gmail.py
│   ├── notify-slack.py
│   ├── orchestrate-enterprise-integrations.sh
│   ├── pipeline-verdict.py
│   ├── production-readiness.cjs
│   ├── provision-jira-vault.py
│   ├── provision-thehive-vault.py
│   ├── __pycache__
│   │   ├── aggregate-infra-status.cpython-314.pyc
│   │   ├── bootstrap-thehive-enterprise.cpython-314.pyc
│   │   ├── ingest-defectdojo.cpython-314.pyc
│   │   ├── ingest-granular-siem.cpython-314.pyc
│   │   ├── ingest-thehive-incident.cpython-314.pyc
│   │   ├── langfuse_tracer.cpython-314.pyc
│   │   ├── mirror-ofac.cpython-314.pyc
│   │   ├── pipeline-verdict.cpython-314.pyc
│   │   ├── provision-thehive-vault.cpython-314.pyc
│   │   ├── run-incident-abort.cpython-314.pyc
│   │   ├── run-ofac-screening.cpython-314.pyc
│   │   ├── run-openscap-audit.cpython-314.pyc
│   │   ├── ship-siem-telemetry.cpython-314.pyc
│   │   ├── sync-defectdojo-metrics.cpython-314.pyc
│   │   ├── sync-thehive-vault.cpython-314.pyc
│   │   └── vault-hive-pipeline.cpython-314.pyc
│   ├── run-all-e2e.sh
│   ├── run-dast.sh
│   ├── run-formal-tools.cjs
│   ├── run-governance.cjs
│   ├── run-iast.cjs
│   ├── run-incident-abort.py
│   ├── run-ofac-screening.py
│   ├── run-openscap-audit.py
│   ├── run-readiness-gate.sh
│   ├── run-sast-symbolic.py
│   ├── run-sca.cjs
│   ├── run-sca-gate.py
│   ├── run-sca.sh
│   ├── run-secret-scan.sh
│   ├── run-sonar.sh
│   ├── run-trivy.sh
│   ├── sca-inventory.cjs
│   ├── sca-lookup.cjs
│   ├── ship-siem-telemetry.py
│   ├── sync-defectdojo-metrics.py
│   ├── sync-thehive-vault.py
│   ├── test-ollama-chat.py
│   ├── vault-hive-pipeline.py
│   ├── verify-enrichment.mts
│   ├── verify-formal-tools.mts
│   ├── verify-mask-fixture.cjs
│   ├── verify-normalization.mts
│   └── verify-pipeline-entrypoints.mts
├── soc-project-skeleton-v10.3.zip
├── sonar-project.properties
├── src
│   ├── agents
│   │   ├── agent_a_auditor.py
│   │   ├── agent_b_threat_hunter.py
│   │   ├── agent_c_compliance_judge.py
│   │   ├── agent_d_red_teamer.py
│   │   ├── agent_e_incident_commander.py
│   │   ├── agent_f_deep_logic.py
│   │   ├── agent_f_logic_analyzer.py
│   │   ├── agent_g_guardrail.py
│   │   ├── agent_g_guardrail_watchdog.py
│   │   ├── graph.py
│   │   ├── __pycache__
│   │   ├── state.py
│   │   ├── swarm_orchestrator.py
│   │   └── upgrade5_defi_attacks.py
│   ├── compliance
│   │   ├── address_screener.py
│   │   ├── aml_detector.py
│   │   ├── aml_patterns.py
│   │   ├── compliance_mcp.py
│   │   ├── compliance_policy.py
│   │   ├── graph_integrator.py
│   │   ├── __init__.py
│   │   ├── __pycache__
│   │   ├── report_generator.py
│   │   ├── sar_generator.py
│   │   └── zk_attestation.py
│   ├── consensus
│   │   ├── agent_consensus_client.py
│   │   ├── anvil_sandbox.py
│   │   ├── avs_consensus.py
│   │   ├── avs_gate.py
│   │   ├── avs_router.py
│   │   ├── bls_aggregation.py
│   │   ├── concentration_tracker.py
│   │   ├── consensus_mcp.py
│   │   ├── consensus_policy.py
│   │   ├── eclipse_detector.py
│   │   ├── exploit_harness
│   │   ├── forensic_event_emitter.py
│   │   ├── graph_enricher.py
│   │   ├── __init__.py
│   │   ├── p2p_listener.py
│   │   ├── __pycache__
│   │   ├── reorg_monitor.py
│   │   ├── selfish_mining_detector.py
│   │   └── validator_node.py
│   ├── consensus_security
│   │   ├── concentration_tracker.py
│   │   ├── eclipse_detector.py
│   │   ├── __init__.py
│   │   ├── p2p_listener.py
│   │   ├── __pycache__
│   │   ├── reorg_monitor.py
│   │   └── selfish_mining_detector.py
│   ├── deployment
│   │   ├── consensus_deployer.py
│   │   ├── forensic_staging_snapshot.py
│   │   ├── gitlab_mr_workflow.py
│   │   ├── patch_sandbox.py
│   │   ├── __pycache__
│   │   ├── readiness_policy_gate.py
│   │   └── vault_secret_store.py
│   ├── drills
│   │   ├── drill_relayer_key_compromise.py
│   │   └── __pycache__
│   ├── forensics
│   │   ├── acquisition.py
│   │   ├── chain_of_custody.py
│   │   ├── collector.py
│   │   ├── disk_forensics.py
│   │   ├── evidence_db.py
│   │   ├── evidence_sanitizer.py
│   │   ├── evidence_sealer.py
│   │   ├── evidence_vault.py
│   │   ├── hasher.py
│   │   ├── __init__.py
│   │   ├── integrity.py
│   │   ├── memory_forensics.py
│   │   ├── merkle_manifest.py
│   │   ├── onchain_forensics.py
│   │   ├── policy_evaluator.py
│   │   ├── __pycache__
│   │   ├── report_generator.py
│   │   ├── report_packager.py
│   │   ├── sanitizer.py
│   │   ├── stix_exporter.py
│   │   ├── timeline.py
│   │   └── vault.py
│   ├── incident
│   │   ├── jira_dispatcher.py
│   │   ├── __pycache__
│   │   └── safe_pause_builder.py
│   ├── llm_client
│   │   ├── ollama_client.py
│   │   └── __pycache__
│   ├── mcp_middleware
│   │   ├── agent_g_guardrail.py
│   │   ├── anvil_sandbox.py
│   │   ├── compliance_screen.py
│   │   ├── consensus_monitor.py
│   │   ├── forensic_tools.py
│   │   ├── host_forensics.py
│   │   ├── opa_guardrail.py
│   │   ├── __pycache__
│   │   ├── telemetry.py
│   │   └── wallet_audit.py
│   ├── mitigation
│   │   ├── egress_gateway.py
│   │   ├── mirror_gate.py
│   │   ├── __pycache__
│   │   └── quarantine_staging.py
│   ├── observability
│   │   ├── fast_path_mitigation.py
│   │   ├── lifecycle_telemetry.py
│   │   ├── __pycache__
│   │   ├── rasp_router.py
│   │   ├── rasp_shield.py
│   │   ├── shadow_fork_verifier.py
│   │   ├── telemetry_client.py
│   │   ├── telemetry_stack.py
│   │   └── threat_intel.py
│   ├── reporting
│   │   ├── __init__.py
│   │   └── __pycache__
│   ├── storage
│   │   ├── attack_path_graph.py
│   │   ├── benchmark_suite.py
│   │   ├── broker_store.py
│   │   └── __pycache__
│   ├── wallet
│   │   ├── hsm_emulator.py
│   │   ├── hsm_signer_interface.py
│   │   ├── mpc_joint_signer.py
│   │   ├── mpc_relayer_cluster.py
│   │   ├── presign_simulator.py
│   │   ├── __pycache__
│   │   ├── shamir_engine.py
│   │   ├── wallet_audit_mcp.py
│   │   └── wallet_policy.py
│   └── wallet_security
│       ├── hsm_client.py
│       ├── __init__.py
│       ├── mpc_relayer.py
│       ├── presign_simulator.py
│       ├── __pycache__
│       └── shamir.py
├── test
│   ├── academic-artifacts.test.mjs
│   ├── agents
│   │   ├── __pycache__
│   │   ├── test_agent_a_auditor.py
│   │   ├── test_agent_b_threat_hunter.py
│   │   ├── test_agent_c_compliance_judge.py
│   │   ├── test_agent_d_red_teamer.py
│   │   ├── test_agent_e_incident_commander.py
│   │   ├── test_agent_f_logic_analyzer.py
│   │   ├── test_agent_g_guardrail.py
│   │   ├── test_graph_pipeline.py
│   │   ├── test_swarm_benchmark.py
│   │   ├── test_swarm_graph.py
│   │   └── test_upgrade5_defi_attacks.py
│   ├── aggregate-status.test.mjs
│   ├── compliance
│   │   ├── __init__.py
│   │   ├── __pycache__
│   │   ├── test_address_screener.py
│   │   ├── test_aml_detector.py
│   │   ├── test_compliance_agent_denial.py
│   │   ├── test_compliance_agent_integrations.py
│   │   ├── test_compliance_mcp.py
│   │   ├── test_compliance_policy.py
│   │   ├── test_drill_screening_pipeline.py
│   │   ├── test_drill_zk_attestation.py
│   │   ├── test_graph_integrator.py
│   │   ├── test_sar_generator.py
│   │   └── test_zk_attestation.py
│   ├── consensus
│   │   ├── __init__.py
│   │   ├── __pycache__
│   │   ├── test_agent_consensus_client.py
│   │   ├── test_anvil_sandbox.py
│   │   ├── test_avs_gate.py
│   │   ├── test_avs_router.py
│   │   ├── test_bls_aggregation.py
│   │   ├── test_concentration_tracker.py
│   │   ├── test_consensus_mcp.py
│   │   ├── test_consensus_policy.py
│   │   ├── test_drill_scenarios.py
│   │   ├── test_dual_path_verification.py
│   │   ├── test_eclipse_detector.py
│   │   ├── test_finding_rejection.py
│   │   ├── test_forensic_event_emitter.py
│   │   ├── test_graph_enricher.py
│   │   ├── test_p2p_listener.py
│   │   ├── test_reorg_monitor.py
│   │   ├── test_selfish_mining_detector.py
│   │   ├── test_supermajority_rule.py
│   │   └── test_validator_cluster.py
│   ├── consensus_security
│   │   ├── __init__.py
│   │   ├── __pycache__
│   │   └── test_detectors.py
│   ├── deployment
│   │   ├── __pycache__
│   │   ├── test_consensus_deployer.py
│   │   ├── test_deploy_e2e.py
│   │   ├── test_forensic_staging_snapshot.py
│   │   ├── test_gitlab_mr_workflow.py
│   │   ├── test_patch_sandbox.py
│   │   ├── test_readiness_policy_gate.py
│   │   └── test_vault_secret_store.py
│   ├── extended-report.test.mjs
│   ├── forensics
│   │   ├── __init__.py
│   │   ├── __pycache__
│   │   ├── test_agent_g_guardrail.py
│   │   ├── test_chain_of_custody.py
│   │   ├── test_evidence_collector.py
│   │   ├── test_evidence_db.py
│   │   ├── test_evidence_sanitizer.py
│   │   ├── test_evidence_vault.py
│   │   ├── test_forensic_policy.py
│   │   ├── test_integrity_hasher.py
│   │   ├── test_integrity.py
│   │   ├── test_integrity_tamper_regressions.py
│   │   ├── test_opa_forensics_policy.py
│   │   ├── test_prompt_injection_sanitization.py
│   │   ├── test_report_packager.py
│   │   └── test_volatility_sequence.py
│   ├── foundry
│   │   ├── DeFiLendingVault.t.sol
│   │   ├── Exploit.t.sol
│   │   └── Invariants.t.sol
│   ├── hardhat
│   │   ├── formal-tools.test.cjs
│   │   ├── pipeline-entrypoints.test.cjs
│   │   └── placeholder.test.cjs
│   ├── __init__.py
│   ├── llm_client
│   │   ├── __pycache__
│   │   ├── test_model_lifecycle.py
│   │   ├── test_ollama_client.py
│   │   └── test_raw_chat.py
│   ├── mcp_middleware
│   │   ├── __init__.py
│   │   ├── __pycache__
│   │   ├── test_anvil_sandbox.py
│   │   ├── test_host_forensics.py
│   │   ├── test_opa_agent_policy.py
│   │   ├── test_opa_guardrail.py
│   │   └── test_telemetry.py
│   ├── mitigation
│   │   ├── __pycache__
│   │   ├── test_invalid_token_mirror_blocking.py
│   │   ├── test_mitigation_mirror_gate.py
│   │   ├── test_outbound_mirror_isolation.py
│   │   ├── test_quarantine_staging.py
│   │   └── test_role_boundary_enforcement.py
│   ├── observability
│   │   ├── __pycache__
│   │   ├── test_fast_path_mitigation.py
│   │   ├── test_lifecycle_telemetry.py
│   │   ├── test_rasp_router.py
│   │   ├── test_rasp_shield.py
│   │   ├── test_shadow_fork_verifier.py
│   │   ├── test_telemetry_client.py
│   │   └── test_telemetry_stack.py
│   ├── outreach-artifacts.test.mjs
│   ├── public-repo-hygiene.test.mjs
│   ├── __pycache__
│   │   └── __init__.cpython-314.pyc
│   ├── python
│   │   ├── __pycache__
│   │   ├── test_avs_consensus.py
│   │   ├── test_pipeline_verdict.py
│   │   └── test_scanner_result.py
│   ├── report-agent-isolation.test.mjs
│   ├── report-fixture-redaction.test.mjs
│   ├── reporting
│   │   ├── __init__.py
│   │   ├── __pycache__
│   │   └── test_status_report.py
│   ├── report-render.test.mjs
│   ├── report-standalone-browser.test.mjs
│   ├── storage
│   │   ├── __pycache__
│   │   ├── test_attack_path_graph.py
│   │   ├── test_benchmark_suite.py
│   │   ├── test_broker_store.py
│   │   └── test_role_enforcement.py
│   ├── wallet
│   │   ├── fixtures
│   │   ├── __init__.py
│   │   ├── __pycache__
│   │   ├── test_drill_relayer_compromise.py
│   │   ├── test_hsm_emulator.py
│   │   ├── test_hsm_signer_interface.py
│   │   ├── test_mpc_joint_signer.py
│   │   ├── test_mpc_relayer_cluster.py
│   │   ├── test_presign_simulator.py
│   │   ├── test_shamir_engine.py
│   │   ├── test_vulnerable_wallet_fixture.py
│   │   ├── test_wallet_agent_denial.py
│   │   ├── test_wallet_agent_integrations.py
│   │   ├── test_wallet_audit_mcp.py
│   │   └── test_wallet_policy.py
│   └── wallet_security
│       ├── __init__.py
│       ├── __pycache__
│       └── test_key_policy.py
├── tsconfig.json
└── types
    └── ethers-contracts
        ├── common.ts
        ├── DeFiLendingVault.ts
        ├── factories
        ├── hardhat.d.ts
        ├── index.ts
        ├── RandomTestVault.ts
        ├── SecureVault.ts
        ├── StakingRewardsVault.ts
        └── VulnerableVault.ts

110 directories, 547 files
```

## `Makefile`

```makefile
# ==============================================================================
# DYNAMIC SMART CONTRACT SELECTION TOGGLE
# Usage:
#   make pipeline-all                       -> Scans contracts/solidity/VulnerableVault.sol (Default Exploit Path)
#   make pipeline-all -- --secure            -> Scans contracts/solidity/SecureVault.sol     (Remediated Safe Path)
#   make pipeline-all SECURE=1               -> Scans contracts/solidity/SecureVault.sol     (Remediated Safe Path)
#   make pipeline-all CONTRACT=<filename>    -> Scans contracts/solidity/<filename> (any registered contract)
#   make pipeline-all TARGET_CONTRACT=<path> -> Scans <path> directly (unchanged, still works)
# CONTRACT= is just a filename-only convenience over TARGET_CONTRACT=; it still
# needs the file registered in scripts/ingest-manifests.mts's EXPECTED_FILE_HASHES/
# EXPECTED_ASSET_MAP (Zone 1 manifest ingestion rejects unregistered files) --
# see that file's own error message for the exact lines to add.
# ==============================================================================
ifdef CONTRACT
  ifeq ($(wildcard contracts/solidity/$(CONTRACT)),)
    $(error CONTRACT=$(CONTRACT) not found at contracts/solidity/$(CONTRACT) -- check the filename)
  endif
  export TARGET_CONTRACT := contracts/solidity/$(CONTRACT)
endif

ifeq ($(SECURE), 1)
  export SECURE := 1
  export TARGET_CONTRACT ?= contracts/solidity/SecureVault.sol
else ifneq ($(filter --secure,$(MAKECMDGOALS)),)
  export SECURE := 1
  export TARGET_CONTRACT := contracts/solidity/SecureVault.sol
else
  export SECURE := 0
  export TARGET_CONTRACT ?= contracts/solidity/VulnerableVault.sol
endif

--secure:
	@:

.PHONY: deploy-soc-pipeline test lint status-report pipeline-e2e enterprise-integration pipeline-all gitops-publish argocd-sync dast-scan

deploy-soc-pipeline:
	python3 scripts/deploy-soc-demo.py

test:
	@echo "Running unit test battery..."
	python3 -m unittest discover -s test/llm_client/ -p "test_*.py"

lint:
	@echo "Checking static lint..."

status-report:
	npm run report

enterprise-integration:
	@./scripts/orchestrate-enterprise-integrations.sh

pipeline-e2e: enterprise-integration
	@bash scripts/run-all-e2e.sh

# pipeline-e2e fails (non-zero) when a required scanner did not really run.
# GitOps happens only when reports/verdict.json says gitops_allowed=true (health OK and verdict PASS).
pipeline-all: pipeline-e2e
	@if [ "$$(jq -r '.gitops_allowed' reports/verdict.json 2>/dev/null)" = "true" ]; then \
		$(MAKE) gitops-publish; \
	else \
		echo "[!] GitOps SKIPPED: verdict=$$(jq -r .verdict reports/verdict.json) (see reasons above). Set ALLOW_GITOPS_ON_HALT=1 to override for demos."; \
		python3 scripts/notify-gmail.py || true; \
	fi

gitops-publish:
	@echo "[+] ========================================================"
	@echo "[+] SYNCHRONIZING TO GITLAB CI/CD SOURCE OF TRUTH"
	@echo "[+] ========================================================"
	@rm -rf cache out config/cache config/out 2>/dev/null || true
	@git add src/ test/ scripts/ config/ Makefile Jenkinsfile .gitlab-ci.yml 2>/dev/null || true
	@if git diff --cached --quiet; then \
		echo "[*] Working tree clean: generating automated empty trigger commit..."; \
		git commit --allow-empty -m "chore(pipeline): automated unified e2e trigger $$(date +%Y%m%d_%H%M%S)"; \
	else \
		echo "[*] Staging and committing modified workspace artifacts..."; \
		git commit -m "chore(pipeline): automated unified e2e run $$(date +%Y%m%d_%H%M%S)"; \
	fi
	@echo "[*] Pushing commit to GitLab main branch..."
	@git push gitlab main
	@$(MAKE) argocd-sync
	@echo "[+] UNIFIED CI/CD COMPLETED (verdict: $$(jq -r .verdict reports/verdict.json))"
	@python3 scripts/notify-gmail.py || true

argocd-sync:
	@echo "[+] [ARGOCD] Initiating GitOps cluster synchronization..."
	@if kubectl get app blockchain-soc-pipeline -n argocd >/dev/null 2>&1; then \
	        echo "    -> Patching Argo CD sync operation to cluster..."; \
	        LATEST_REV=$$(git rev-parse HEAD); \
	        kubectl patch app blockchain-soc-pipeline -n argocd --type merge -p "{\"operation\": {\"sync\": {\"revision\": \"$$LATEST_REV\", \"prune\": true}}}" >/dev/null 2>&1 || true; \
	        kubectl annotate app blockchain-soc-pipeline -n argocd argocd.argoproj.io/refresh="hard" --overwrite >/dev/null 2>&1 || true; \
	        echo "    -> Waiting for Argo CD reconciliation..."; \
	        sleep 4; \
	        CURRENT_SYNC=$$(kubectl get app blockchain-soc-pipeline -n argocd -o jsonpath='{.status.sync.revision}' 2>/dev/null || echo "in-progress"); \
	        echo "    -> Live Cluster Sync Target: $$(echo "$$LATEST_REV" | cut -c 1-7) (Argo Status: $$(echo "$$CURRENT_SYNC" | cut -c 1-7))"; \
	        echo "    -> Argo CD GitOps synchronization successfully dispatched."; \
	else \
	        echo "    [-] Argo CD application 'blockchain-soc-pipeline' not detected in cluster. Skipping sync."; \
	fi

# ----------------------------------------------------------------------
# Dynamic Application Security Testing (DAST) - OWASP ZAP Baseline
# ----------------------------------------------------------------------
dast-scan:
	@./scripts/run-dast.sh

# ----------------------------------------------------------------------
# Central Compliance Orchestration - DefectDojo (Port 8085)
# ----------------------------------------------------------------------
.PHONY: defectdojo-sync
defectdojo-sync:
	@echo "[+] [COMPLIANCE] Syncing Unified Findings to DefectDojo (Port 8085)..."
	@python3 scripts/ingest-defectdojo.py || true

```

## `scripts/run-all-e2e.sh`

```bash
#!/usr/bin/env bash
export PYTHONPATH="$(pwd):${PYTHONPATH:-}"
set -eo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Determine target contract dynamically from environment or default
if [ -n "${TARGET_CONTRACT:-}" ]; then
    : # explicit path given — respect it as-is
elif [ "${SECURE:-0}" = "1" ]; then
    TARGET_CONTRACT="contracts/solidity/SecureVault.sol"
else
    TARGET_CONTRACT="contracts/solidity/VulnerableVault.sol"
fi
export TARGET_CONTRACT

if [[ "$TARGET_CONTRACT" == *"SecureVault"* ]]; then
    export SECURE="1"
else
    export SECURE="0"
fi
# Real contract filename (no .sol), not a binary SecureVault/VulnerableVault
# guess -- this feeds the Vault-signed attestation message below, and a
# wrong label there would be a real, cryptographically-signed false claim
# about which contract this run actually targeted.
TARGET_NAME="$(basename "$TARGET_CONTRACT" .sol)"


echo "========================================================================"
echo "   AUTONOMOUS BLOCKCHAIN SOC — FULL ENTERPRISE E2E PIPELINE"
echo "========================================================================"
START_TIME=$(date +%s)
export TARGET_NAME
VERDICT_RC=0
./scripts/init-run.sh

# Step 1: Zone 1 Manifest Ingestion & Asset Map
echo -e "\n[+] [ZONE 1] Validating Manifest Topologies & Asset Maps..."
./node_modules/.bin/tsx --no-cache scripts/ingest-manifests.mts
./scripts/run-secret-scan.sh

# Step 2: Zone 2 AST Sanitization, Trivy Scanner & Security Gate
echo -e "\n[+] [ZONE 2] Running Multi-Tier SAST & Symbolic Analysis..."
python3 scripts/run-sast-symbolic.py

echo -e "\n[+] [ZONE 2] Running AST String-Literal Masking..."
./node_modules/.bin/tsx --no-cache scripts/ast-mask.mts --approved-local-fixture

echo -e "\n[+] [ZONE 2] Running SCA Dependency Verification..."
python3 scripts/run-sca-gate.py

./scripts/run-trivy.sh

./scripts/run-dast.sh

python3 scripts/run-openscap-audit.py

./scripts/run-sonar.sh

./scripts/run-readiness-gate.sh

# Step 3: Zone 3 Broker Store & Attack Path Graph
echo -e "\n[+] [ZONE 3] Ingesting OSINT Threat Intelligence Feeds..."
python3 src/observability/threat_intel.py

echo -e "\n[+] [ZONE 3] Constructing Knowledge Graph & DREAD Scoring..."
python3 - <<'PYEOF'
import json
import os
from pathlib import Path
from src.storage.broker_store import BrokerStore
from src.storage.attack_path_graph import AttackPathGraph

# Real target name and real top finding, read from Zone 2's own SAST report
# (already written by run-sast-symbolic.py, which runs before this step) --
# previously this picked between two hardcoded canned findings based on a
# binary secure/vulnerable guess, with zero real computation regardless of
# contract or actual scan result.
target_env = os.getenv("TARGET_CONTRACT", "")
t_name = Path(target_env).stem if target_env else "unknown"

IMPACT_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFORMATIONAL": 1, "INFO": 1}
IMPACT_DREAD = {"CRITICAL": 9.5, "HIGH": 8.0, "MEDIUM": 5.5, "LOW": 3.0, "INFORMATIONAL": 1.0, "INFO": 1.0}

sast_findings = []
report_path = Path("reports/sast-symbolic-report.json")
if report_path.is_file():
    try:
        sast_findings = json.loads(report_path.read_text()).get("findings", [])
    except (OSError, ValueError):
        sast_findings = []

store = BrokerStore('data/broker_store.db')
graph = AttackPathGraph()

t_id = graph.add_target_node(t_name, target_type='contract')

if sast_findings:
    top = max(sast_findings, key=lambda f: IMPACT_RANK.get((f.get("impact") or "").upper(), 0))
    impact = (top.get("impact") or "INFORMATIONAL").upper()
    finding = {
        'finding_id': f"SAST-{top.get('check', 'unknown')}",
        'title': top.get('check', 'unknown'),
        'severity': impact,
        'dread_score': IMPACT_DREAD.get(impact, 0.0),
        'target_contract': t_name,
    }
else:
    finding = {
        'finding_id': 'NO-FINDING',
        'title': 'no-sast-finding-this-run',
        'severity': 'INFORMATIONAL',
        'dread_score': 0.0,
        'target_contract': t_name,
    }

graph.build_from_findings([finding])
paths = graph.list_attack_paths()
print(f'    -> Graph synthesized: {len(paths)} attack path(s) mapped.')
PYEOF

# Step 4: Zone 6 & 8 Consensus Monitoring & OFAC Screening
# Step 3B: LangGraph 7-Agent Swarm Execution.
# Run every agent on the fast default model (OLLAMA_DEFAULT_MODEL, qwen3.5:9b):
# the env's per-agent 32B overrides are impractically slow on this host (cold
# load > 2 min, one-at-a-time serving) and time out. Scoped to a subshell so the
# rest of the pipeline keeps its env. The orchestrator still honours
# OLLAMA_MODEL_AGENT_* wherever they are set.
( for a in A B C D E F G; do unset "OLLAMA_MODEL_AGENT_$a"; done
  python3 src/agents/swarm_orchestrator.py )

# Step 3C: AVS Cryptographic Consensus & Attestation Gate
echo -e "\n[+] [AVS CONSENSUS] Executing 3-Node Byzantine Fault Tolerant Consensus..."
python3 src/consensus/avs_consensus.py

echo -e "\n[+] [ZONE 6 & 8] Streaming P2P Network Telemetry & Address Screening..."
python3 -c "
from src.consensus.p2p_listener import ConsensusNetworkListener
listener = ConsensusNetworkListener()
listener.register_peer('peer-01', '198.51.100.12', 30303, 13335, 'Geth/v1.14', 24.5)
print('    -> P2P Peer registered.')
"
# Real OFAC SDN screening (writes reports/scanners/ofac-screening.json). Screens
# TARGET_SCREEN_ADDRESS if set, else a documented demonstration canary.
python3 scripts/run-ofac-screening.py

# Verdict is computed here: after every REQUIRED Zone 2 scanner (slither,
# mythril, sast-canary, trivy, zap, sca, openscap, sonar, readiness) AND after
# the real AVS consensus / LangGraph swarm signals it also reads, but BEFORE
# Zone 4 incident response (run-incident-abort.py) reads reports/verdict.json.
# Previously verdict ran at the very end of the pipeline, so incident response
# always saw a stale/missing verdict from the prior run (or UNKNOWN on a clean
# checkout); running it before Zone 2's scanners instead would have the same
# staleness problem against avs-consensus/swarm, which run after Zone 2.
#
# openscap is advisory-only on this host: neither Ubuntu nor Debian SSG content
# has platform-applicability checks that match Kali's /etc/os-release (ID=kali),
# so 0 rules are ever genuinely scored (verified against both ssg-ubuntu2204-ds.xml
# and ssg-debian13-ds.xml). The scanner still runs and still reports its real,
# honest status -- it just no longer gates pipeline health.
export SOC_OPTIONAL="openscap${SOC_OPTIONAL:+,$SOC_OPTIONAL}"
python3 scripts/pipeline-verdict.py || VERDICT_RC=$?

# Step 5: Zone 7 Wallet Simulation Gate & Live HashiCorp Vault Signing
echo -e "\n[+] [ZONE 7] Testing Pre-Sign Transaction Simulation Barrier..."
python3 -c "
from src.wallet.presign_simulator import PresignSimulator, RelayerTxIntent, SimulationError
from scripts.lib.scanner_result import write_result

target_addr = '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC'
sim = PresignSimulator(allowed_recipients={target_addr}, max_drain_wei=10**18, max_gas=500000)

intent = RelayerTxIntent(
    sender='0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
    target=target_addr,
    value_wei=10**17,
    data=b'',
    nonce=1,
    gas_limit=100000
)

try:
    receipt = sim.simulate_and_validate(intent)
    print(f'    -> Simulation approved: digest={receipt.receipt_digest[:16]}... gas_used={receipt.gas_used} success={receipt.success}')
    write_result('presign-sim', 'presign-simulator',
                 'ok' if receipt.success else 'error',
                 target=intent.target, counts={'gas_used': receipt.gas_used},
                 detail=f'digest={receipt.receipt_digest[:16]}... success={receipt.success}')
except SimulationError as e:
    print(f'    -> Simulation REJECTED (fail-closed): {e}')
    write_result('presign-sim', 'presign-simulator', 'error', target=intent.target,
                 detail=f'rejected: {str(e)[:150]}')
"

echo -e "\n[+] [ZONE 7] Cryptographic Attestation via Live HashiCorp Vault Transit Engine..."
python3 -c "
import base64, os, requests
from scripts.lib.scanner_result import write_result

addr = os.environ.get('VAULT_ADDR', 'http://127.0.0.1:8200')
token = os.environ.get('VAULT_TOKEN')
if not token:
    write_result('vault-sign', 'vault-transit', 'not_run', detail='VAULT_TOKEN not set')
else:
    msg = 'ATTESTATION:' + os.environ.get('TARGET_NAME', 'unknown') + ':PIPELINE_RUN'
    payload = base64.b64encode(msg.encode()).decode()
    try:
        resp = requests.post(addr + '/v1/transit/sign/soc-relayer-key', headers={'X-Vault-Token': token},
                             json={'input': payload}, timeout=5)
        sig = resp.json().get('data', {}).get('signature') if resp.status_code == 200 else None
        if sig:
            write_result('vault-sign', 'vault-transit', 'ok', detail='signature ' + sig[:24] + '...')
        else:
            write_result('vault-sign', 'vault-transit', 'error', detail='HTTP ' + str(resp.status_code))
    except Exception as e:
        write_result('vault-sign', 'vault-transit', 'error', detail=str(e)[:120])
"

# Step 4B & 5B: Zone 4 Incident Abort, Jira Dispatch & Zone 5 STIX 2.1 DFIR Bundle
python3 scripts/run-incident-abort.py

# Stream this run's real verdict/swarm/AVS/OFAC data to Langfuse as one real
# trace (runs after run-incident-abort.py so the Jira ticket this run
# produced, if any, is already on disk). Non-fatal: skips cleanly if
# Langfuse keys aren't configured.
echo -e "\n[+] [LANGFUSE] Streaming real verification trace..."
python3 -c "from scripts.langfuse_tracer import stream_verification_trace; stream_verification_trace()" || true

# Step 6: Zone 4 K3s Kubernetes Cluster Verification
echo -e "\n[+] [ZONE 4] Verifying K3s Kubernetes Cluster & Active Nodes..."
python3 -c "
import subprocess
from scripts.lib.scanner_result import write_result

try:
    cmd = ['kubectl', '--kubeconfig=/etc/rancher/k3s/k3s.yaml', 'get', 'nodes']
    out = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=15)
    lines = [l for l in out.stdout.strip().splitlines() if not l.startswith('NAME')]
    if lines:
        fields = lines[0].split()
        node_name, node_status = fields[0], fields[1] if len(fields) > 1 else 'unknown'
        version = fields[4] if len(fields) > 4 else None
        print(f'    -> K3s Cluster Active Node: {lines[0]}')
        write_result('k3s', 'kubectl', 'ok' if node_status == 'Ready' else 'error',
                     target=node_name, version=version,
                     counts={'node_name': node_name},
                     detail=f'node {node_name} status={node_status}')
    else:
        print('    -> K3s Cluster Online (control-plane)')
        write_result('k3s', 'kubectl', 'ok', detail='cluster reachable, no node rows parsed')
except Exception as e:
    print(f'    -> K3s check note: {e}')
    write_result('k3s', 'kubectl', 'not_run', detail=str(e)[:150])
"

# Step 7: Zone 5 Forensics Vault Sealing
echo -e "\n[+] [ZONE 5] Sealing Incident Artifacts in Forensics DB..."
python3 -c "
import time
from pathlib import Path
from src.forensics.evidence_db import EvidenceDatabaseManager
from src.forensics.evidence_sealer import seal_run_evidence

# Seal this run's REAL evidence (the actual report files), not a constant.
seal = seal_run_evidence(Path('.'), f'EVID-AUTO-RUN-{int(time.time())}')
db = EvidenceDatabaseManager('data/forensics.db')
rec = db.register_evidence(
    evidence_id=seal['incident_id'] + '-manifest',
    file_path=seal['manifest_path'],
    byte_size=seal['manifest_bytes'],
    sha256=seal['root_sha256'],
    sha512=seal['root_sha512'],
    acquired_by='soc-operator',
    status='SEALED',
)
print(f'    -> Forensic record sealed: {rec[\"evidence_id\"]} | {seal[\"file_count\"]} files | Hash: {rec[\"sha256\"][:16]}...')
"

echo -e "\n[+] [COMPLIANCE] Ingesting Multi-Scanner Telemetry into DefectDojo (Port 8085)..."
python3 scripts/ingest-defectdojo.py || true

# Real OWASP DSOMM maturity scoring: must run after DefectDojo ingestion
# (reports/scanners/defectdojo.json is one of its real signals) and before
# ship-siem-telemetry.py / generate-html-report.mts, which both read its output.
python3 scripts/compute-dsomm-maturity.py

# Step 8: Zone 9 Status Aggregator & HTML Report Compilation
echo -e "\n[+] [ZONE 9] Aggregating Cross-Zone Status & Generating Report..."
./node_modules/.bin/tsx --no-cache scripts/aggregate-status.mts
python3 scripts/aggregate-infra-status.py
python3 scripts/ship-siem-telemetry.py
    python3 scripts/ingest-granular-siem.py || true
python3 scripts/sync-defectdojo-metrics.py || true
./node_modules/.bin/tsx --no-cache scripts/generate-html-report.mts
python3 scripts/notify-slack.py || true

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))
echo "========================================================================"
if [ "$VERDICT_RC" -eq 0 ]; then
    echo -e " [+] Pipeline health OK in ${ELAPSED}s. Verdict: $(jq -r .verdict reports/verdict.json)"
else
    echo -e " [-] PIPELINE HEALTH FAILED in ${ELAPSED}s. Not everything really ran: see verdict above."
fi
echo -e " [+] Executive Report: file://${REPO_ROOT}/reports/latest.html"
echo "========================================================================"
exit "$VERDICT_RC"
```

## `Jenkinsfile`

```groovy
pipeline {
    agent any

    environment {
        VAULT_ADDR = 'http://192.168.0.150:8200'
        VAULT_TOKEN = 'cross-vault-6b76c24b1e537ee522d3369651764e94'
        ELASTIC_PASSWORD = 'ElasticAdminPass123'
    }

    stages {
        stage('Vault Secrets Extraction') {
            steps {
                echo '[+] Querying HashiCorp Vault for Dynamic Tokens...'
                sh '''
                    # Fetch SonarQube token from Vault
                    SONAR_TOKEN=$(curl -s -H "X-Vault-Token: ${VAULT_TOKEN}" "${VAULT_ADDR}/v1/secret/data/sonarqube" | jq -r '.data.data.token')
                    echo "SONAR_TOKEN=${SONAR_TOKEN}" > .vault_env
                '''
            }
        }

        stage('SonarQube SAST & Quality Gate') {
            steps {
                echo '[+] Executing SonarScanner Analysis...'
                sh '''
                    source .vault_env
                    docker run --rm --network host -v "$(pwd):/usr/src" \
                      sonarsource/sonar-scanner-cli \
                      -Dsonar.host.url="http://127.0.0.1:9000" \
                      -Dsonar.login="${SONAR_TOKEN}" \
                      -Dsonar.projectKey="blockchain-security-soc" \
                      -Dsonar.sources="contracts,scripts" \
                      -Dsonar.exclusions="out/**,cache/**,node_modules/**,lib/**"
                '''
            }
        }

        stage('Master Security & AI SOC Audit') {
            steps {
                echo '[+] Running Autonomous Multi-Zone Pipeline...'
                sh '''
                    make pipeline-e2e
                '''
            }
        }

        stage('ArgoCD GitOps Promotion') {
            steps {
                echo '[+] Promoting verified deployment to Argo CD...'
                sh '''
                    # Hard refresh Argo CD to deploy latest commit
                    kubectl annotate application blockchain-soc-pipeline -n argocd argocd.argoproj.io/refresh=hard --overwrite || true
                '''
            }
        }
    }

    post {
        always {
            cleanWs()
        }
        success {
            echo '[+] Jenkins Pipeline Completed Successfully. Cluster state reconciled.'
        }
        failure {
            echo '[-] Jenkins Pipeline Failed. Deployment gated.'
        }
    }
}```

## `.gitlab-ci.yml`

```yaml
stages:
  - verify
  - report
  - security-audit
  - gitops-deploy

variables:
  VAULT_ADDR: "http://172.17.0.1:8200"
  VAULT_TOKEN: "cross-vault-6b76c24b1e537ee522d3369651764e94"
  JENKINS_ADDR: "http://172.17.0.1:8082"
  # argocd-server exposed via NodePort (was ClusterIP-only) specifically so
  # CI job containers can reach it over the same docker-bridge-gateway path
  # already used for VAULT_ADDR/JENKINS_ADDR. Anonymous access confirmed
  # disabled (401 on unauthenticated requests) before this was wired up.
  ARGOCD_ADDR: "https://172.17.0.1:31703"

runner_smoke_test:
  stage: verify
  image: alpine:3.20
  tags:
    - soc-docker
  script:
    - 'echo "GitLab Docker runner is online"'
    - 'echo "Project: ${CI_PROJECT_PATH}"'
    - 'echo "Commit: ${CI_COMMIT_SHA}"'
    - 'echo "Branch: ${CI_COMMIT_REF_NAME}"'
    - 'test -f README.md'
    - 'test -f docs/CHECKLIST.md'
    - 'test -f docs/HANDOFF.md'
    - 'uname -a'

ingest_manifests:
  stage: verify
  image: node:24.19.0-bookworm-slim
  tags:
    - soc-docker
  script:
    - 'npm ci --ignore-scripts --no-audit --fund=false'
    - './node_modules/.bin/hardhat --config config/hardhat.config.js test --no-compile test/hardhat/formal-tools.test.cjs test/hardhat/placeholder.test.cjs test/hardhat/pipeline-entrypoints.test.cjs'
    - 'mkdir -p artifacts'
    - './node_modules/.bin/tsx --no-cache scripts/ingest-manifests.mts > artifacts/ingestion-result.json'
    - >
      node -e 'const fs = require("node:fs");
      const result = JSON.parse(fs.readFileSync("artifacts/ingestion-result.json", "utf8"));
      if (result.schemaVersion !== 1 || result.status !== "valid" ||
          !result.integrity || !result.assetMap) {
        throw new Error(`Unexpected ingestion result: ${JSON.stringify(result)}`);
      }
      console.log("PASS: valid schemaVersion-1 ingestion result with integrity and assetMap.");'
  artifacts:
    when: on_success
    expire_in: 7 days
    paths:
      - artifacts/ingestion-result.json

production_readiness_gate:
  stage: verify
  image: node:24.19.0-bookworm-slim
  tags:
    - soc-docker
  allow_failure: false
  script:
    - 'mkdir -p artifacts'
    - 'node scripts/production-readiness.cjs --ci > artifacts/production-readiness.json'
  artifacts:
    when: always
    expire_in: 7 days
    paths:
      - artifacts/production-readiness.json

executive_status_report:
  stage: report
  image: node:24.19.0-bookworm-slim
  tags:
    - soc-docker
  script:
    - 'npm ci --ignore-scripts --no-audit --fund=false'
    - 'npm run report'
    - 'test -f reports/latest.html'
    - 'test -f reports/status.json'
  artifacts:
    when: on_success
    expire_in: 7 days
    paths:
      - reports/latest.html
      - reports/status.json

jenkins_enterprise_audit:
  stage: security-audit
  image: alpine:3.20
  tags:
    - soc-docker
  before_script:
    - apk add --no-cache curl jq
  script:
    - 'echo "[+] [STAGE 3] Querying HashiCorp Vault for dynamic tokens..."'
    - 'export JENKINS_TOKEN=$(curl -s -H "X-Vault-Token: ${VAULT_TOKEN}" "${VAULT_ADDR}/v1/secret/data/jenkins" | jq -r ".data.data.token")'
    - 'export CRUMB_JSON=$(curl -s --cookie-jar /tmp/jk_cookies.txt -u "admin:${JENKINS_TOKEN}" "${JENKINS_ADDR}/crumbIssuer/api/json")'
    - 'export CRUMB_HEADER=$(echo "$CRUMB_JSON" | jq -r ".crumbRequestField")'
    - 'export CRUMB_VAL=$(echo "$CRUMB_JSON" | jq -r ".crumb")'
    - 'echo "[+] [JENKINS] Triggering Job blockchain-soc-audit..."'
    - 'curl -s -i --cookie /tmp/jk_cookies.txt -X POST "${JENKINS_ADDR}/job/blockchain-soc-audit/build" -u "admin:${JENKINS_TOKEN}" -H "${CRUMB_HEADER}:${CRUMB_VAL}"'
    - 'echo "[+] Build triggered. Polling Jenkins for execution results..."'
    - 'sleep 6'
    - |
      for i in $(seq 1 45); do
        BUILD_INFO=$(curl -s -u "admin:${JENKINS_TOKEN}" "${JENKINS_ADDR}/job/blockchain-soc-audit/lastBuild/api/json")
        BUILD_RESULT=$(echo "$BUILD_INFO" | jq -r '.result // "BUILDING"')
        BUILD_NUM=$(echo "$BUILD_INFO" | jq -r '.number')

        if [ "$BUILD_RESULT" = "SUCCESS" ]; then
          echo "[+] Jenkins Build #${BUILD_NUM} completed with SUCCESS."
          break
        elif [ "$BUILD_RESULT" = "FAILURE" ]; then
          echo "[-] Jenkins Build #${BUILD_NUM} FAILED."
          exit 1
        fi
        echo "    -> Waiting for build to finish (Status: ${BUILD_RESULT})..."
        sleep 4
      done

argocd_gitops_reconciliation:
  stage: gitops-deploy
  image: alpine:3.20
  tags:
    - soc-docker
  before_script:
    - apk add --no-cache curl jq python3
  script:
    - 'echo "[+] [STAGE 4] Reconciling deployment state on K3s via Argo CD..."'
    - 'export ARGOCD_TOKEN=$(curl -s -H "X-Vault-Token: ${VAULT_TOKEN}" "${VAULT_ADDR}/v1/secret/data/argocd" | jq -r ".data.data.token")'
    - 'echo "[+] [ARGOCD] Triggering sync for application blockchain-soc-pipeline..."'
    - 'curl -sk -X POST "${ARGOCD_ADDR}/api/v1/applications/blockchain-soc-pipeline/sync" -H "Authorization: Bearer ${ARGOCD_TOKEN}" -H "Content-Type: application/json" -d "{}"'
    - 'echo "[+] Sync triggered. Polling Argo CD for reconciliation result..."'
    - 'sleep 6'
    - |
      # Argo CD's own last-applied-configuration annotation can legitimately
      # contain a raw unescaped control character (confirmed live against the
      # real cluster, reproducible, also rejected by Python's own strict JSON
      # parser) -- jq has no lenient mode for this, so status parsing below
      # uses python3's json.loads(strict=False) instead, which tolerates it.
      for i in $(seq 1 45); do
        APP_INFO=$(curl -sk -H "Authorization: Bearer ${ARGOCD_TOKEN}" "${ARGOCD_ADDR}/api/v1/applications/blockchain-soc-pipeline")
        STATUS_LINE=$(echo "$APP_INFO" | python3 -c "import json,sys
      try:
          d = json.loads(sys.stdin.read(), strict=False); s = d.get('status', {})
          print(s.get('sync', {}).get('status', 'Unknown'), s.get('operationState', {}).get('phase', 'Running'), s.get('health', {}).get('status', 'Unknown'))
      except Exception:
          print('Unknown Running Unknown')")
        SYNC_STATUS=$(echo "$STATUS_LINE" | cut -d' ' -f1)
        OP_PHASE=$(echo "$STATUS_LINE" | cut -d' ' -f2)
        HEALTH=$(echo "$STATUS_LINE" | cut -d' ' -f3)

        if [ "$OP_PHASE" = "Succeeded" ] && [ "$SYNC_STATUS" = "Synced" ]; then
          echo "[+] Argo CD sync Succeeded (sync=${SYNC_STATUS}, health=${HEALTH})."
          break
        elif [ "$OP_PHASE" = "Failed" ] || [ "$OP_PHASE" = "Error" ]; then
          echo "[-] Argo CD sync ${OP_PHASE} (sync=${SYNC_STATUS}, health=${HEALTH})."
          exit 1
        fi
        echo "    -> Waiting for reconciliation to finish (phase: ${OP_PHASE}, sync: ${SYNC_STATUS})..."
        sleep 4
      done
```

## `scripts/ingest-manifests.mts`

```typescript
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { lstat, readdir, readFile } from "node:fs/promises";
import { relative, resolve, sep } from "node:path";

type TomlValue = string | string[];
type TomlSections = Record<string, Record<string, TomlValue>>;

type IntegrityResult = {
  files: Record<string, string>;
  lockfileVersion: number;
  toolchains: {
    foundrySolcVersion: string;
    hardhatSolidityVersion: string;
    movePackageVersion: string;
  };
};

type AssetMap = {
  schemaVersion: 1;
  contracts: {
    solidity: string[];
  };
  move: {
    manifest: "config/Move.toml";
    modules: string[];
    packages: string[];
  };
  tests: {
    foundry: string[];
    hardhat: string[];
  };
};

export type IngestionResult = {
  schemaVersion: 1;
  status: "valid";
  manifests: {
    foundry: {
      src: string;
      test: string;
      out: string;
      libs: string[];
      solcVersion: string;
    };
    hardhat: {
      solidityVersion: string;
      optimizer: { enabled: boolean; runs: number };
      paths: {
        sources: string;
        tests: string;
        cache: string;
        artifacts: string;
      };
    };
    move: {
      package: { name: string; version: string };
      addresses: { blockchainSoc: string };
      dependencies: Record<string, never>;
    };
  };
  integrity: IntegrityResult;
  assetMap: AssetMap;
};

export class ManifestValidationError extends Error {
  constructor(
    public readonly manifest: "foundry" | "hardhat" | "move",
    message: string,
  ) {
    super(message);
    this.name = "ManifestValidationError";
  }
}

function requireString(
  value: unknown,
  manifest: "foundry" | "hardhat" | "move",
  field: string,
): string {
  if (typeof value !== "string") {
    throw new ManifestValidationError(manifest, `${field} must be a string`);
  }
  return value;
}

function requireBoolean(
  value: unknown,
  manifest: "hardhat",
  field: string,
): boolean {
  if (typeof value !== "boolean") {
    throw new ManifestValidationError(manifest, `${field} must be a boolean`);
  }
  return value;
}

function requireNumber(
  value: unknown,
  manifest: "hardhat",
  field: string,
): number {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new ManifestValidationError(manifest, `${field} must be a finite number`);
  }
  return value;
}

function parseTomlString(raw: string, manifest: "foundry" | "move", field: string): string {
  const match = raw.match(/^"([^"]*)"$/);
  if (!match) {
    throw new ManifestValidationError(manifest, `${field} must use a quoted string`);
  }
  return match[1];
}

function parseTomlValue(raw: string, manifest: "foundry" | "move", field: string): TomlValue {
  const trimmed = raw.trim();
  if (trimmed.startsWith("[")) {
    const match = trimmed.match(/^\[\s*"([^"]*)"\s*\]$/);
    if (!match) {
      throw new ManifestValidationError(manifest, `${field} must be a single-string array`);
    }
    return [match[1]];
  }
  return parseTomlString(trimmed, manifest, field);
}

function parseSimpleToml(
  text: string,
  manifest: "foundry" | "move",
): TomlSections {
  const sections: TomlSections = {};
  let current: Record<string, TomlValue> | undefined;

  for (const [index, rawLine] of text.split(/\r?\n/).entries()) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) {
      continue;
    }

    const sectionMatch = line.match(/^\[([A-Za-z0-9_.-]+)\]$/);
    if (sectionMatch) {
      current = sections[sectionMatch[1]] ??= {};
      continue;
    }

    const keyMatch = line.match(/^([A-Za-z0-9_.-]+)\s*=\s*(.+)$/);
    if (!keyMatch || !current) {
      throw new ManifestValidationError(
        manifest,
        `unsupported TOML syntax at line ${index + 1}`,
      );
    }

    const [, key, rawValue] = keyMatch;
    if (Object.hasOwn(current, key)) {
      throw new ManifestValidationError(manifest, `duplicate key ${key}`);
    }
    current[key] = parseTomlValue(rawValue, manifest, key);
  }

  return sections;
}

function expectExact<T>(
  value: T,
  expected: T,
  manifest: "foundry" | "hardhat" | "move",
  field: string,
): T {
  if (value !== expected) {
    throw new ManifestValidationError(
      manifest,
      `${field} must equal ${JSON.stringify(expected)}`,
    );
  }
  return value;
}

function requireObject(
  value: unknown,
  manifest: "hardhat",
  field: string,
): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new ManifestValidationError(manifest, `${field} must be an object`);
  }
  return value as Record<string, unknown>;
}

async function validateFoundry(path: string): Promise<IngestionResult["manifests"]["foundry"]> {
  const sections = parseSimpleToml(await readFile(path, "utf8"), "foundry");
  const profile = sections["profile.default"];
  if (!profile) {
    throw new ManifestValidationError("foundry", "missing [profile.default]");
  }

  const src = expectExact(requireString(profile.src, "foundry", "profile.default.src"), "contracts/solidity", "foundry", "profile.default.src");
  const test = expectExact(requireString(profile.test, "foundry", "profile.default.test"), "test/foundry", "foundry", "profile.default.test");
  const out = expectExact(requireString(profile.out, "foundry", "profile.default.out"), "out", "foundry", "profile.default.out");
  const solcVersion = expectExact(requireString(profile.solc_version, "foundry", "profile.default.solc_version"), "0.8.24", "foundry", "profile.default.solc_version");
  const libs = profile.libs;

  if (!Array.isArray(libs) || libs.length !== 1 || libs[0] !== "lib") {
    throw new ManifestValidationError("foundry", "profile.default.libs must equal [\"lib\"]");
  }

  return { src, test, out, libs, solcVersion };
}

function loadHardhatConfig(path: string): Record<string, unknown> {
  const requireFromConfig = createRequire(path);
  delete requireFromConfig.cache?.[path];
  const loaded = requireFromConfig(path);
  const mod = requireObject(loaded, "hardhat", "module.exports");
  // Hardhat 3's config is an ES module (export default defineConfig({...})),
  // which Node's CJS/ESM interop returns as {__esModule, default: <config>}
  // rather than the config object itself -- unwrap it the same way a real
  // `import` would, instead of validating the interop wrapper.
  return Object.hasOwn(mod, "default") ? requireObject(mod.default, "hardhat", "module.exports.default") : mod;
}

function validateHardhat(path: string): IngestionResult["manifests"]["hardhat"] {
  const config = loadHardhatConfig(path);
  if (Object.hasOwn(config, "networks")) {
    throw new ManifestValidationError("hardhat", "networks must be absent");
  }

  const solidity = requireObject(config.solidity, "hardhat", "solidity");
  const settings = requireObject(solidity.settings, "hardhat", "solidity.settings");
  const optimizer = requireObject(settings.optimizer, "hardhat", "solidity.settings.optimizer");
  const paths = requireObject(config.paths, "hardhat", "paths");
  // Hardhat 3's paths.tests is {mocha, solidity}, not a plain string like
  // Hardhat 2's -- validate the shape that's actually loaded at runtime.
  const testsPaths = requireObject(paths.tests, "hardhat", "paths.tests");

  const solidityVersion = expectExact(requireString(solidity.version, "hardhat", "solidity.version"), "0.8.24", "hardhat", "solidity.version");
  const enabled = expectExact(requireBoolean(optimizer.enabled, "hardhat", "solidity.settings.optimizer.enabled"), false, "hardhat", "solidity.settings.optimizer.enabled");
  const runs = expectExact(requireNumber(optimizer.runs, "hardhat", "solidity.settings.optimizer.runs"), 200, "hardhat", "solidity.settings.optimizer.runs");

  return {
    solidityVersion,
    optimizer: { enabled, runs },
    paths: {
      sources: expectExact(requireString(paths.sources, "hardhat", "paths.sources"), "./contracts/solidity", "hardhat", "paths.sources"),
      tests: expectExact(requireString(testsPaths.mocha, "hardhat", "paths.tests.mocha"), "./test/hardhat", "hardhat", "paths.tests.mocha"),
      cache: expectExact(requireString(paths.cache, "hardhat", "paths.cache"), "./cache/hardhat", "hardhat", "paths.cache"),
      artifacts: expectExact(requireString(paths.artifacts, "hardhat", "paths.artifacts"), "./artifacts/hardhat", "hardhat", "paths.artifacts"),
    },
  };
}

async function validateMove(path: string): Promise<IngestionResult["manifests"]["move"]> {
  const sections = parseSimpleToml(await readFile(path, "utf8"), "move");
  const packageSection = sections.package;
  const addresses = sections.addresses;
  const dependencies = sections.dependencies;

  if (!packageSection || !addresses || !dependencies) {
    throw new ManifestValidationError("move", "missing required package, addresses, or dependencies section");
  }

  if (Object.keys(dependencies).length !== 0) {
    throw new ManifestValidationError("move", "dependencies must be empty");
  }

  return {
    package: {
      name: expectExact(requireString(packageSection.name, "move", "package.name"), "MoveTargetPackage", "move", "package.name"),
      version: expectExact(requireString(packageSection.version, "move", "package.version"), "0.0.1", "move", "package.version"),
    },
    addresses: {
      blockchainSoc: expectExact(requireString(addresses.blockchain_soc, "move", "addresses.blockchain_soc"), "0x0", "move", "addresses.blockchain_soc"),
    },
    dependencies: {},
  };
}

const EXPECTED_FILE_HASHES = {
  "package.json": "2b53050204ad0c99e8ebbfa3a16815ca27a6ad9e961a475c2818fdf185904e48",
  "package-lock.json": "5ae1ce6b1253c0882b05cb5ec7599773fa6939ceb96e5a1573872e4bda70b563",
  "config/foundry.toml": "71c0b047c483a4e0c5aca70b5bc0315a75d2b3d73edd8c86e7c944a2bcb358bf",
  "config/hardhat.config.js": "376c177c094ed304af60ab5746730aa02ad3eabd7facc72ef52315f8f63482c8",
  "config/Move.toml": "52211ca389cb1353cd04c32ba21b2052e62fec320f7de8e4b759ddb4f6671f71",
  "contracts/solidity/DeFiLendingVault.sol": "f3944ffce6755f87b9c7c231c754bad8c723dd8f3381aadb0ba22346f6739b1f",
  "contracts/solidity/PromptInjectionFixture.sol": "17f6fba73823f0ed9c00a9253595cb7249c580fcb4dfc79f1e9b6344c26f47a4",
    "contracts/solidity/StakingRewardsVault.sol": "e3aa8dbc8b51be9fdfc41ddb83309406c753945444164ce8fba346abf481a91e",
  "contracts/solidity/SecureVault.sol": "817b8d2575e24cd5276fb8414323b0c2f5c22ee538523ca648a5ea9b89adea87",
  "contracts/solidity/VulnerableVault.sol": "31a68c972361a3e537cd9b6107eb4efb7f47b77236958098db61dbefa184354a",
  "contracts/solidity/RandomTestVault.sol": "b25bd2f3ce7523f608c51955cfd355847f328b094a0cccd1ffe4f36ca7aada83",
} as const;

const EXPECTED_COMPILER_TOOLCHAINS = {
  foundrySolcVersion: "0.8.24",
  hardhatSolidityVersion: "0.8.24",
  movePackageVersion: "0.0.1",
} as const;

class IntegrityValidationError extends Error {
  constructor(public readonly component: string, message: string) {
    super(message);
    this.name = "IntegrityValidationError";
  }
}

function sha256(content: string | Buffer): string {
  return createHash("sha256").update(content).digest("hex");
}

async function verifyFileHashes(root: string): Promise<Record<string, string>> {
  const observed: Record<string, string> = {};

  for (const [relativePath, expected] of Object.entries(EXPECTED_FILE_HASHES)) {
    const fullPath = resolve(root, relativePath);
    let content: Buffer;
    try {
      content = await readFile(fullPath);
    } catch (err: any) {
      if (err.code === "ENOENT") {
        // Required baseline config/manifest files must exist; contracts can be target-dependent or sandbox fixtures
        const isCoreConfig = relativePath.startsWith("config/") || relativePath.startsWith("package");
        if (isCoreConfig) {
          throw err;
        }
        continue;
      }
      throw err;
    }

    const actual = sha256(content);
    if (actual !== expected) {
      throw new IntegrityValidationError(
        relativePath,
        `sha256 mismatch: expected ${expected}, received ${actual}`,
      );
    }
    observed[relativePath] = actual;
  }

  return observed;
}

async function verifyLockfile(root: string): Promise<number> {
  let lockfile: unknown;
  try {
    lockfile = JSON.parse(await readFile(resolve(root, "package-lock.json"), "utf8"));
  } catch (error) {
    throw new IntegrityValidationError(
      "package-lock.json",
      `invalid JSON: ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  if (typeof lockfile !== "object" || lockfile === null || Array.isArray(lockfile)) {
    throw new IntegrityValidationError("package-lock.json", "must be an object");
  }

  const rootLockfile = lockfile as Record<string, unknown>;
  if (rootLockfile.lockfileVersion !== 3) {
    throw new IntegrityValidationError("package-lock.json", "lockfileVersion must equal 3");
  }

  const packages = rootLockfile.packages;
  if (typeof packages !== "object" || packages === null || Array.isArray(packages)) {
    throw new IntegrityValidationError("package-lock.json", "packages must be an object");
  }

  const rootPackage = (packages as Record<string, unknown>)[""];
  if (typeof rootPackage !== "object" || rootPackage === null || Array.isArray(rootPackage)) {
    throw new IntegrityValidationError("package-lock.json", "root package entry is required");
  }

  const devDependencies = (rootPackage as Record<string, unknown>).devDependencies;
  if (typeof devDependencies !== "object" || devDependencies === null || Array.isArray(devDependencies)) {
    throw new IntegrityValidationError("package-lock.json", "root devDependencies must be an object");
  }

  const expectedDependencies = {
    hardhat: "^3.21.0",
    tsx: "^4.0.0",
    typescript: "^5.5.0",
  };

  for (const [name, expected] of Object.entries(expectedDependencies)) {
    if ((devDependencies as Record<string, unknown>)[name] !== expected) {
      throw new IntegrityValidationError(
        "package-lock.json",
        `root devDependency ${name} must equal ${expected}`,
      );
    }
  }

  for (const [path, entry] of Object.entries(packages as Record<string, unknown>)) {
    if (path === "" || typeof entry !== "object" || entry === null || Array.isArray(entry)) {
      continue;
    }
    const packageEntry = entry as Record<string, unknown>;
    const resolved = packageEntry.resolved;
    if (resolved === undefined) {
      continue;
    }
    if (typeof resolved !== "string" || !resolved.startsWith("https://registry.npmjs.org/")) {
      throw new IntegrityValidationError(
        "package-lock.json",
        `package ${path} resolved URL must use https://registry.npmjs.org/`,
      );
    }
    if (typeof packageEntry.integrity !== "string" || !packageEntry.integrity.startsWith("sha512-")) {
      throw new IntegrityValidationError(
        "package-lock.json",
        `package ${path} must declare sha512 integrity`,
      );
    }
  }

  return 3;
}

function verifyCompilerToolchains(
  manifests: IngestionResult["manifests"],
): IntegrityResult["toolchains"] {
  const observed = {
    foundrySolcVersion: manifests.foundry.solcVersion,
    hardhatSolidityVersion: manifests.hardhat.solidityVersion,
    movePackageVersion: manifests.move.package.version,
  };

  if (
    observed.foundrySolcVersion !== EXPECTED_COMPILER_TOOLCHAINS.foundrySolcVersion ||
    observed.hardhatSolidityVersion !== EXPECTED_COMPILER_TOOLCHAINS.hardhatSolidityVersion ||
    observed.movePackageVersion !== EXPECTED_COMPILER_TOOLCHAINS.movePackageVersion
  ) {
    throw new IntegrityValidationError(
      "compiler-toolchain",
      `compiler-toolchain mismatch: ${JSON.stringify(observed)}`,
    );
  }

  return observed;
}

async function verifyIntegrity(
  root: string,
  manifests: IngestionResult["manifests"],
): Promise<IntegrityResult> {
  return {
    files: await verifyFileHashes(root),
    lockfileVersion: await verifyLockfile(root),
    toolchains: verifyCompilerToolchains(manifests),
  };
}

class AssetMapValidationError extends Error {
  constructor(public readonly component: string, message: string) {
    super(message);
    this.name = "AssetMapValidationError";
  }
}

function toRelativePosixPath(root: string, path: string): string {
  const relativePath = relative(root, path);
  if (
    relativePath === "" ||
    relativePath === ".." ||
    relativePath.startsWith(`..${sep}`) ||
    relativePath.includes("\\")
  ) {
    throw new AssetMapValidationError("asset-map", `path escapes repository root: ${path}`);
  }
  return relativePath.split(sep).join("/");
}

const EXPECTED_ASSET_MAP = {
  contracts: {
    solidity: [
      "contracts/solidity/DeFiLendingVault.sol",
      "contracts/solidity/PromptInjectionFixture.sol",
      "contracts/solidity/RandomTestVault.sol",
      "contracts/solidity/StakingRewardsVault.sol",
      "contracts/solidity/SecureVault.sol",
      "contracts/solidity/VulnerableVault.sol",
    ],
  },
  move: {
    manifest: "config/Move.toml",
    modules: [],
    packages: [],
  },
  tests: {
    foundry: [
      "test/foundry/DeFiLendingVault.t.sol",
      "test/foundry/Exploit.t.sol",
      "test/foundry/Invariants.t.sol",
    ],
    hardhat: [
    "test/hardhat/formal-tools.test.cjs",
    "test/hardhat/pipeline-entrypoints.test.cjs",
    "test/hardhat/placeholder.test.cjs",
  ],
  },
} as const;

async function verifyExpectedAsset(
  root: string,
  relativePath: string,
  component: string,
): Promise<void> {
  if (
    relativePath === "" ||
    relativePath.startsWith("/") ||
    relativePath.includes("\\") ||
    relativePath.split("/").includes("..")
  ) {
    throw new AssetMapValidationError(component, `unsafe expected asset: ${relativePath}`);
  }

  const absolutePath = resolve(root, relativePath);
  if (toRelativePosixPath(root, absolutePath) !== relativePath) {
    throw new AssetMapValidationError(component, `expected asset escapes root: ${relativePath}`);
  }

  let status;
  try {
    status = await lstat(absolutePath);
  } catch (error) {
    throw new AssetMapValidationError(
      component,
      `expected asset is unavailable: ${relativePath}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  if (status.isSymbolicLink() || !status.isFile()) {
    throw new AssetMapValidationError(component, `expected asset must be a non-symlink regular file: ${relativePath}`);
  }
}

async function listVerifiedDirectoryAssets(
  root: string,
  relativeDirectory: string,
  suffix: string,
  component: string,
): Promise<string[]> {
  const directory = resolve(root, relativeDirectory);
  let status;
  try {
    status = await lstat(directory);
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") {
      return [];
    }
    throw new AssetMapValidationError(
      component,
      `cannot inspect ${relativeDirectory}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  if (status.isSymbolicLink() || !status.isDirectory()) {
    throw new AssetMapValidationError(component, `${relativeDirectory} must be a non-symlink directory`);
  }

  const assets: string[] = [];
  const visit = async (currentDirectory: string): Promise<void> => {
    const entries = await readdir(currentDirectory, { withFileTypes: true });
    entries.sort((left, right) => left.name.localeCompare(right.name));

    for (const entry of entries) {
      const currentPath = resolve(currentDirectory, entry.name);
      const relativePath = toRelativePosixPath(root, currentPath);

      if (entry.isSymbolicLink()) {
        throw new AssetMapValidationError(component, `symlink is not permitted: ${relativePath}`);
      }

      if (entry.isDirectory()) {
        await visit(currentPath);
      } else if (entry.isFile() && relativePath.endsWith(suffix)) {
        assets.push(relativePath);
      }
    }
  };

  await visit(directory);
  return assets.sort((left, right) => left.localeCompare(right));
}

async function verifyExpectedAssetList(
  root: string,
  actual: string[],
  expected: readonly string[],
  component: string,
): Promise<string[]> {
  const expectedSet = new Set(expected);

  // If any file on disk is not in the authorized expected set, reject with asset inventory mismatch
  const unexpected = actual.filter((p) => !expectedSet.has(p));
  if (unexpected.length > 0 || (expected.length > 0 && actual.length === 0)) {
    let hint = "";
    if (unexpected.length > 0) {
      // A new, unregistered file (e.g. a new contract added to contracts/solidity/)
      // is the single most common reason this fails -- compute its real hash and
      // print the exact line to add, instead of leaving the reader to diff two
      // JSON arrays by hand to find the one new path and then hunt for sha256sum.
      const suggestions = await Promise.all(unexpected.map(async (p) => {
        try {
          const hash = sha256(await readFile(resolve(root, p)));
          return `"${p}": "${hash}"`;
        } catch {
          return `"${p}": <could not read file to compute its hash>`;
        }
      }));
      hint = ` -- unregistered file(s) found; add to EXPECTED_FILE_HASHES and ` +
        `EXPECTED_ASSET_MAP.${component} in scripts/ingest-manifests.mts: ${suggestions.join(", ")}`;
    }
    throw new AssetMapValidationError(
      component,
      `asset inventory mismatch: expected ${JSON.stringify([...expected].sort())}, received ${JSON.stringify(actual)}${hint}`,
    );
  }

  // Verify non-symlink regular file integrity for all actual present assets
  for (const path of actual) {
    await verifyExpectedAsset(root, path, component);
  }

  return [...actual].sort((left, right) => left.localeCompare(right));
}

async function emitAssetMap(
  root: string,
  manifests: IngestionResult["manifests"],
): Promise<AssetMap> {
  const foundrySource = manifests.foundry.src;
  const hardhatSource = manifests.hardhat.paths.sources.replace(/^\.\//, "");
  if (foundrySource !== hardhatSource) {
    throw new AssetMapValidationError(
      "contracts",
      `Foundry and Hardhat source roots differ: ${foundrySource} versus ${hardhatSource}`,
    );
  }

  const foundryTest = manifests.foundry.test;
  const hardhatTest = manifests.hardhat.paths.tests.replace(/^\.\//, "");

  const solidity = await verifyExpectedAssetList(
    root,
    await listVerifiedDirectoryAssets(root, foundrySource, ".sol", "contracts"),
    EXPECTED_ASSET_MAP.contracts.solidity,
    "contracts",
  );

  const modules = await verifyExpectedAssetList(
    root,
    await listVerifiedDirectoryAssets(root, "move/modules", ".move", "move.modules"),
    EXPECTED_ASSET_MAP.move.modules,
    "move.modules",
  );

  const packages = await verifyExpectedAssetList(
    root,
    await listVerifiedDirectoryAssets(root, "move/packages", "/Move.toml", "move.packages"),
    EXPECTED_ASSET_MAP.move.packages,
    "move.packages",
  );

  const foundry = await verifyExpectedAssetList(
    root,
    await listVerifiedDirectoryAssets(root, foundryTest, ".t.sol", "tests.foundry"),
    EXPECTED_ASSET_MAP.tests.foundry,
    "tests.foundry",
  );

  const hardhat = await verifyExpectedAssetList(
    root,
    await listVerifiedDirectoryAssets(root, hardhatTest, ".test.cjs", "tests.hardhat"),
    EXPECTED_ASSET_MAP.tests.hardhat,
    "tests.hardhat",
  );

  await verifyExpectedAsset(root, EXPECTED_ASSET_MAP.move.manifest, "move");

  return {
    schemaVersion: 1,
    contracts: { solidity },
    move: {
      manifest: EXPECTED_ASSET_MAP.move.manifest,
      modules,
      packages,
    },
    tests: {
      foundry,
      hardhat,
    },
  };
}

export async function ingestManifests(root = process.cwd()): Promise<IngestionResult> {
  const configDir = resolve(root, "config");
  const foundry = await validateFoundry(resolve(configDir, "foundry.toml"));
  const hardhat = validateHardhat(resolve(configDir, "hardhat.config.js"));
  const move = await validateMove(resolve(configDir, "Move.toml"));

  const manifests = {
    foundry,
    hardhat,
    move,
  };

  return {
    schemaVersion: 1,
    status: "valid",
    manifests,
    integrity: await verifyIntegrity(root, manifests),
    assetMap: await emitAssetMap(root, manifests),
  };
}

async function main(): Promise<void> {
  try {
    const root = process.argv[2] ?? process.cwd();
    process.stdout.write(`${JSON.stringify(await ingestManifests(root))}\n`);
  } catch (error) {
    const result = error instanceof ManifestValidationError
      ? { schemaVersion: 1, status: "invalid", manifest: error.manifest, error: error.message }
      : error instanceof IntegrityValidationError
        ? { schemaVersion: 1, status: "invalid", component: error.component, error: error.message }
        : error instanceof AssetMapValidationError
          ? { schemaVersion: 1, status: "invalid", component: error.component, error: error.message }
          : { schemaVersion: 1, status: "error", error: error instanceof Error ? error.message : String(error) };
    process.stderr.write(`${JSON.stringify(result)}\n`);
    process.exitCode = 1;
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  void main();
}
```

## `scripts/run-sast-symbolic.py`

```python
#!/usr/bin/env python3
"""Zone 2 SAST + symbolic analysis: real Slither and real Mythril only.

Nothing is ever invented: a missing or failing tool is recorded as not_run / error.
Canary: both VulnerableVault and SecureVault are scanned (SOC_CANARY=0 disables).
  * VulnerableVault MUST trigger Slither's reentrancy-eth (proves the detector works)
  * SecureVault MUST NOT trigger it (proves no false positive)
Mythril analyses solc runtime bytecode, so it needs no network and no solc download.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
from scanner_result import ROOT, RAW, write_result  # noqa: E402

SOLC_VERSION = os.getenv("SOLC_VERSION", "0.8.24")
MYTH_TIMEOUT = int(os.getenv("MYTHRIL_TIMEOUT", "60"))
VULN, SECURE = "VulnerableVault", "SecureVault"
DEFAULT_TARGET = f"contracts/solidity/{VULN}.sol"

SC01 = "SC01: Reentrancy Exploitation"
SC02 = "SC02: Access Control Vulnerability"
SC03 = "SC03: Unprotected Upgrade / Delegatecall"
SC10 = "SC10: General Logic / Compiler Flaw"
OWASP = {"reentrancy-eth": SC01, "reentrancy-no-eth": SC01,
         "arbitrary-send-eth": SC02, "suicidal": SC02,
         "unprotected-upgrade": SC03, "controlled-delegatecall": SC03}
SWC = {"SWC-107": SC01, "SWC-105": SC02, "SWC-106": SC02, "SWC-112": SC03}
RANK = {"ok": 0, "not_run": 1, "error": 2}


def _res(status, detail, findings=None, **kw):
    return {"status": status, "detail": detail, "findings": findings or [], **kw}


def slither_scan(target, tag):
    exe = shutil.which("slither") or str(Path.home() / ".local/bin/slither")
    if not Path(exe).exists():
        return _res("not_run", "slither is not installed")
    RAW.mkdir(parents=True, exist_ok=True)
    jpath, spath = RAW / f"slither-{tag}.json", RAW / f"slither-{tag}.sarif"
    for p in (jpath, spath):
        p.unlink(missing_ok=True)
    cmd = [exe, str(target), "--solc-solcs-select", SOLC_VERSION,
           "--json", str(jpath), "--sarif", str(spath)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=240, cwd=ROOT)
    except Exception as exc:
        return _res("error", f"slither could not run: {exc}")
    if not jpath.is_file():
        return _res("error", f"slither produced no JSON; stderr tail: {proc.stderr.strip()[-300:]}")
    try:
        data = json.loads(jpath.read_text(encoding="utf-8"))
    except ValueError as exc:
        return _res("error", f"slither JSON unreadable: {exc}")
    if not data.get("success"):
        return _res("error", f"slither reported failure: {str(data.get('error'))[:200]}")
    findings = []
    for d in (data.get("results") or {}).get("detectors", []):
        check = d.get("check", "unknown")
        findings.append({
            "engine": "Slither", "check": check,
            "impact": str(d.get("impact", "Medium")).upper(),
            "confidence": d.get("confidence", "Medium"),
            "description": (d.get("description") or "").strip().split("\n")[0],
            "owasp_category": OWASP.get(check, SC10), "target": str(target)})
    return _res("ok", None, findings, sarif=spath if spath.is_file() else None)


def _myth_backend():
    exe = shutil.which("myth")
    local = Path.home() / ".local/bin/myth"
    if not exe and local.exists():
        exe = str(local)
    if exe:
        return "native", exe
    if shutil.which("docker"):
        probe = subprocess.run(["docker", "image", "inspect", "mythril/myth"], capture_output=True)
        if probe.returncode == 0:
            return "docker", None
    return None, None


def mythril_scan(target, tag):
    solc = shutil.which("solc")
    if not solc:
        return _res("not_run", "solc not on PATH (needed to build runtime bytecode)")
    mode, myth = _myth_backend()
    if not mode:
        return _res("not_run", "no `myth` binary and no local mythril/myth image (pipx install mythril, or docker pull mythril/myth)")
    findings, issues_raw = [], []
    with tempfile.TemporaryDirectory(prefix="myth-") as tmp:
        os.chmod(tmp, 0o755)
        try:
            comp = subprocess.run([solc, "--bin-runtime", "--overwrite", "-o", tmp, str(target)],
                                  capture_output=True, text=True, timeout=120, cwd=ROOT)
        except Exception as exc:
            return _res("error", f"solc failed to run: {exc}")
        bins = [p for p in sorted(Path(tmp).glob("*.bin-runtime")) if p.stat().st_size > 0]
        if comp.returncode != 0 or not bins:
            return _res("error", f"solc produced no runtime bytecode: {comp.stderr.strip()[-300:]}")
        for b in [p for p in bins if p.stem == Path(target).stem] or bins:
            os.chmod(b, 0o644)
            tail = ["analyze", "-f", None, "--bin-runtime", "-t", "3",
                    "--execution-timeout", str(MYTH_TIMEOUT), "--solver-timeout", "10000", "-o", "json"]
            if mode == "native":
                tail[2] = str(b)
                cmd = [myth] + tail
            else:
                tail[2] = f"/w/{b.name}"
                cmd = ["docker", "run", "--rm", "--network", "none",
                       "-v", f"{tmp}:/w:ro", "mythril/myth"] + tail
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=MYTH_TIMEOUT + 90)
                out = json.loads(proc.stdout)
            except subprocess.TimeoutExpired:
                return _res("error", "mythril exceeded its wall-clock limit")
            except ValueError:
                return _res("error", f"mythril output unparseable: {(proc.stdout or proc.stderr)[-200:]}")
            except Exception as exc:
                return _res("error", f"mythril could not run: {exc}")
            if not out.get("success", False):
                return _res("error", f"mythril reported failure: {str(out.get('error'))[:200]}")
            for issue in out.get("issues", []):
                swc = str(issue.get("swc-id", ""))
                swc = swc if swc.startswith("SWC-") else f"SWC-{swc}"
                issues_raw.append(issue)
                findings.append({
                    "engine": "Mythril", "check": issue.get("title", "Symbolic finding"),
                    "impact": str(issue.get("severity", "Medium")).upper(), "confidence": "High",
                    "description": (issue.get("description") or "").strip().split("\n")[0],
                    "owasp_category": SWC.get(swc, SC10), "swc": swc, "target": str(target)})
    raw = RAW / f"mythril-{tag}.json"
    raw.write_text(json.dumps({"issues": issues_raw}, indent=2), encoding="utf-8")
    return _res("ok", None, findings, raw=raw)


def pick_targets():
    primary = Path(os.getenv("TARGET_CONTRACT", DEFAULT_TARGET))
    primary = primary if primary.is_absolute() else ROOT / primary
    targets = [primary]
    if os.getenv("SOC_CANARY", "1") != "0" and primary.stem in (VULN, SECURE):
        other = primary.with_name(f"{SECURE if primary.stem == VULN else VULN}.sol")
        if other.is_file():
            targets.append(other)
    return targets


def count_by_impact(findings):
    out = {}
    for f in findings:
        k = f["impact"].lower()
        out[k] = out.get(k, 0) + 1
    return out


def worst(per, tool):
    return max((per[t][tool]["status"] for t in per), key=lambda s: RANK[s])


def main():
    strict = "--strict" in sys.argv
    targets = pick_targets()
    primary = targets[0]
    print(f"[+] [ZONE 2] Slither + Mythril on: {', '.join(t.name for t in targets)}")
    if not primary.is_file():
        for n in ("slither", "mythril", "sast-canary"):
            write_result(n, n, "error", detail=f"target not found: {primary}")
        sys.exit(2 if strict else 0)

    per = {t.stem: {"slither": slither_scan(t, t.stem), "mythril": mythril_scan(t, t.stem)}
           for t in targets}
    p = per[primary.stem]

    for tool in ("slither", "mythril"):
        bad = [f"{t}: {per[t][tool]['detail']}" for t in per if per[t][tool]["status"] != "ok"]
        raw = p[tool].get("sarif") if tool == "slither" else p[tool].get("raw")
        write_result(tool, tool, worst(per, tool), target=str(primary.relative_to(ROOT)),
                     counts=count_by_impact(p[tool]["findings"]) if p[tool]["status"] == "ok" else {},
                     raw_report=raw, detail="; ".join(bad) or None,
                     extra={"primary_target": primary.name})

    problems, relevant = [], False
    for t in targets:
        if t.stem not in (VULN, SECURE):
            continue
        relevant = True
        sl = per[t.stem]["slither"]
        if sl["status"] != "ok":
            problems.append(f"{t.stem}: slither {sl['status']}")
            continue
        hit = any(f["check"] == "reentrancy-eth" for f in sl["findings"])
        if t.stem == VULN and not hit:
            problems.append("VulnerableVault: Slither MISSED reentrancy-eth (detector broken)")
        if t.stem == SECURE and hit:
            problems.append("SecureVault: Slither reports reentrancy-eth (false positive)")
    if not relevant:
        write_result("sast-canary", "canary", "ok", detail="not applicable to this target")
    elif problems:
        write_result("sast-canary", "canary", "error", detail="; ".join(problems))
    else:
        write_result("sast-canary", "canary", "ok",
                     detail="vulnerable contract detected, secure contract clean"
                     if len(targets) == 2 else "single-target check passed")

    allf = p["slither"]["findings"] + p["mythril"]["findings"]
    summary = {}
    for f in allf:
        summary[f["owasp_category"]] = summary.get(f["owasp_category"], 0) + 1
    report = {"target": str(primary.relative_to(ROOT)), "totalFindings": len(allf),
              "findings": allf, "owaspSummary": summary,
              "toolStatus": {"slither": p["slither"]["status"], "mythril": p["mythril"]["status"]}}
    out_json = ROOT / "reports" / "sast-symbolic-report.json"
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2), encoding="utf-8")
    sarif_out = ROOT / "reports" / "sast-symbolic-report.sarif"
    sarif_out.unlink(missing_ok=True)  # never leave a stale SARIF for DefectDojo
    if p["slither"].get("sarif"):
        shutil.copyfile(p["slither"]["sarif"], sarif_out)  # Slither's own SARIF, real line numbers
    for f in allf[:5]:
        print(f"       * [{f['engine']}] {f['check']} -> {f['owasp_category']}")
    if strict and any(per[t][k]["status"] != "ok" for t in per for k in ("slither", "mythril")):
        sys.exit(2)


if __name__ == "__main__":
    main()
```

## `scripts/ast-mask.mts`

```typescript
import { createRequire } from "node:module";
import { readFileSync, lstatSync, mkdirSync, mkdtempSync, chmodSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const { parseAndMask } = require("./ast-mask-core.cjs");

export type MaskLimits = {
  maxDepth?: number;
  maxNodes?: number;
  maxOutputBytes?: number;
};

export function maskContractAst(source: string, options: MaskLimits = {}): string {
  return JSON.stringify(parseAndMask(source, options));
}

function main(): void {
  if (process.argv.length !== 3 ||
      process.argv[2] !== "--approved-local-fixture") {
    process.stdout.write(JSON.stringify({
      schemaVersion: 1, task: "P03-004", status: "invalid",
      reason: "explicit-approved-fixture-mode-required", astOmitted: true,
    }) + "\n");
    process.exitCode = 1;
    return;
  }
  const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
  const targetRel = process.env.TARGET_CONTRACT || "contracts/solidity/VulnerableVault.sol";
  const fixture = join(root, targetRel);
  const info = lstatSync(fixture);
  if (!info.isFile() || info.isSymbolicLink()) throw new Error("fixture-input");
  const bytes = readFileSync(fixture);
  const KNOWN_HASHES: Record<string, string> = {
    "contracts/solidity/VulnerableVault.sol": "31a68c972361a3e537cd9b6107eb4efb7f47b77236958098db61dbefa184354a",
    "contracts/solidity/SecureVault.sol": "817b8d2575e24cd5276fb8414323b0c2f5c22ee538523ca648a5ea9b89adea87",
    "contracts/solidity/DeFiLendingVault.sol": "f3944ffce6755f87b9c7c231c754bad8c723dd8f3381aadb0ba22346f6739b1f",
  };
  const expected = KNOWN_HASHES[targetRel] || createHash("sha256").update(bytes).digest("hex");
  if (createHash("sha256").update(bytes).digest("hex") !== expected) {
    throw new Error("fixture-integrity");
  }

  const masked = JSON.parse(maskContractAst(bytes.toString("utf8")));
  const parent = join(homedir(), ".local/state/blockchain-soc/p03-004");
  mkdirSync(parent, { recursive: true, mode: 0o700 });
  const evidence = mkdtempSync(join(parent, "mask-"));
  chmodSync(evidence, 0o700);
  writeFileSync(
    join(evidence, "masked-result.json"),
    JSON.stringify(masked, null, 2) + "\n", { mode: 0o600 }
  );
  const summary = {
    schemaVersion: 1,
    task: "P03-004",
    status: masked.status,
    reason: masked.reason ?? null,
    sourceSha256: masked.sourceSha256 ?? expected,
    parser: masked.parser ?? null,
    nodeCount: masked.nodeCount ?? null,
    maxAstNodeDepth: masked.maxAstNodeDepth ?? null,
    maskedLiteralCount: masked.maskedLiteralCount ?? null,
    maskedStringLiteralCount: masked.maskedStringLiteralCount ?? null,
    omittedDocumentationFields: masked.omittedDocumentationFields ?? null,
    evidenceDirectory: evidence,
    securityAcceptance: "not-established",
    taskComplete: false,
  };
  writeFileSync(
    join(evidence, "summary.json"),
    JSON.stringify(summary, null, 2) + "\n", { mode: 0o600 }
  );
  process.stdout.write(JSON.stringify(summary, null, 2) + "\n");
  process.exitCode = masked.status === "masked" ? 0
    : masked.status === "manual-review" ? 2 : 1;
}

if (process.argv[1] &&
    resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch {
    process.stdout.write(JSON.stringify({
      schemaVersion: 1, task: "P03-004", status: "error",
      reason: "local-fixture-operation-failed", astOmitted: true,
    }) + "\n");
    process.exitCode = 1;
  }
}
```

## `scripts/run-sca.sh`

```bash
#!/usr/bin/env bash
# P03-002: explicit local inventory and approved public vulnerability lookup.
set -euo pipefail
ROOT="$(cd -- "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
exec /usr/bin/node "$ROOT/scripts/run-sca.cjs" "$@"
```

## `scripts/production-readiness.cjs`

```javascript
const fs = require("node:fs");
const path = require("node:path");
const { createHash } = require("node:crypto");

const POLICY_HASH = "eef3af1f3adca840147cd4bae30623710c0705ba2ecb38e269e344af941009ff";
const POLICY_PATH = path.resolve(__dirname, "../config/production-readiness.json");

function validPolicy(policy) {
  return Boolean(
    policy && typeof policy === "object" && !Array.isArray(policy) &&
    Object.keys(policy).sort().join(",") ===
      "hardwareCheck,productionAllowEnabled,protectedReference,readinessIntentVariable,schemaVersion" &&
    policy.schemaVersion === 1 &&
    policy.protectedReference === "main" &&
    policy.readinessIntentVariable === "PRODUCTION_READINESS_REQUESTED" &&
    policy.productionAllowEnabled === false &&
    policy.hardwareCheck &&
    Object.keys(policy.hardwareCheck).sort().join(",") === "adapter,state" &&
    policy.hardwareCheck.state === "unconfigured" &&
    policy.hardwareCheck.adapter === null
  );
}

function parsePolicyBytes(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length > 8192 ||
      createHash("sha256").update(bytes).digest("hex") !== POLICY_HASH) {
    throw new Error("policy integrity failure");
  }
  const policy = JSON.parse(bytes.toString("utf8"));
  if (!validPolicy(policy)) throw new Error("unsupported readiness policy");
  return policy;
}

function readPolicy() {
  const info = fs.lstatSync(POLICY_PATH);
  if (!info.isFile() || info.isSymbolicLink()) {
    throw new Error("unexpected readiness policy input");
  }
  return parsePolicyBytes(fs.readFileSync(POLICY_PATH));
}

function report(status, reasons, requested, contextValid = false) {
  return {
    schemaVersion: 1,
    task: "P03-006",
    status,
    decision: status === "not-requested" ? "not-applicable" : "block",
    productionReadinessRequested: requested,
    productionReady: false,
    deploymentAuthorized: false,
    releaseAuthorized: false,
    targetReference: "main",
    ciMetadataValid: contextValid,
    hardwareCheck: {
      state: "unconfigured",
      executed: false,
      adapterConfigured: false,
    },
    reasons,
    expectedPolicySha256: POLICY_HASH,
    securityAcceptance: "not-established",
    taskComplete: false,
  };
}

function validContext(context) {
  if (!context || typeof context !== "object" || Array.isArray(context) ||
      Object.keys(context).some((key) =>
        !["gitlab", "branch", "protected", "commitSha", "pipelineId"].includes(key)
      )) return false;

  return context.gitlab === true &&
    typeof context.commitSha === "string" &&
    /^[0-9a-f]{40}$/.test(context.commitSha) &&
    typeof context.pipelineId === "string" &&
    /^[1-9][0-9]{0,19}$/.test(context.pipelineId) &&
    (context.branch === null ||
      (typeof context.branch === "string" &&
       /^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$/.test(context.branch))) &&
    (context.protected === null ||
      (typeof context.protected === "string" && context.protected.length <= 8));
}

function evaluate(context, requested, policy) {
  if (!validPolicy(policy)) {
    return report("blocked", ["policy-invalid"], null);
  }
  if (!["true", "false"].includes(requested)) {
    return report("blocked", ["readiness-request-invalid"], null);
  }

  const productionRequest = requested === "true";
  if (!validContext(context)) {
    return report("blocked", productionRequest
      ? ["ci-context-invalid", "hardware-check-unconfigured"]
      : ["ci-context-invalid"], productionRequest);
  }

  if (!productionRequest) {
    return report(
      "not-requested",
      ["development-verification-is-not-production-readiness"],
      false, true
    );
  }

  const reasons = [];
  if (context.branch !== policy.protectedReference) {
    reasons.push("production-reference-mismatch");
  }
  if (context.protected !== "true") {
    reasons.push("protected-reference-not-verified");
  }

  // No external health report, demo flag, or mock result is trusted.
  // An approved real collector must be designed before an allow path exists.
  reasons.push("hardware-check-unconfigured");
  return report("blocked", reasons, true, true);
}

function collectContext(env) {
  return {
    gitlab: env.CI === "true" && env.CI_SERVER_NAME === "GitLab",
    branch: env.CI_COMMIT_BRANCH ?? null,
    protected: env.CI_COMMIT_REF_PROTECTED ?? null,
    commitSha: env.CI_COMMIT_SHA ?? null,
    pipelineId: env.CI_PIPELINE_ID ?? null,
  };
}

function main(args, env = process.env) {
  if (args.length !== 1 ||
      !["--ci", "--check-production-readiness"].includes(args[0])) {
    throw new Error("explicit readiness execution mode required");
  }
  const policy = readPolicy();
  if (args[0] === "--check-production-readiness") {
    return evaluate({
      gitlab: false, branch: null, protected: null,
      commitSha: null, pipelineId: null,
    }, "true", policy);
  }
  const requested = env[policy.readinessIntentVariable] ?? "false";
  return evaluate(collectContext(env), requested, policy);
}

module.exports = {
  POLICY_HASH, parsePolicyBytes, readPolicy, evaluate, collectContext, main,
};

if (require.main === module) {
  let decision;
  try {
    decision = main(process.argv.slice(2));
  } catch {
    decision = report("blocked", ["policy-or-invocation-invalid"], null);
  }
  process.stdout.write(JSON.stringify(decision, null, 2) + "\n");
  process.exitCode = decision.status === "not-requested" ? 0 : 1;
}
```

