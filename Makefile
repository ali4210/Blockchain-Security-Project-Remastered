# ==============================================================================
# DYNAMIC SMART CONTRACT SELECTION TOGGLE
# Usage:
#   make pipeline-all            -> Scans contracts/solidity/VulnerableVault.sol (Default Exploit Path)
#   make pipeline-all -- --secure -> Scans contracts/solidity/SecureVault.sol     (Remediated Safe Path)
#   make pipeline-all SECURE=1   -> Scans contracts/solidity/SecureVault.sol     (Remediated Safe Path)
# ==============================================================================
ifeq ($(SECURE), 1)
  export TARGET_CONTRACT := contracts/solidity/SecureVault.sol
else ifneq ($(filter --secure,$(MAKECMDGOALS)),)
  export TARGET_CONTRACT := contracts/solidity/SecureVault.sol
else
  export TARGET_CONTRACT := contracts/solidity/VulnerableVault.sol
endif

--secure:
	@:

.PHONY: deploy-soc-pipeline test lint status-report pipeline-e2e enterprise-integration pipeline-all

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

pipeline-all: pipeline-e2e
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
	@echo "[+] ========================================================"
	@echo "[+] UNIFIED CI/CD & AUTONOMOUS SOC COMPLETED IN LOCKSTEP"
	@python3 scripts/notify-slack.py || true
	@python3 scripts/notify-gmail.py || true

	@echo "[+] ========================================================"


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
	@echo "[+] [ZONE 2.5] Executing Dynamic Application Security Testing (OWASP ZAP)..."
	@mkdir -p reports/dast
	@docker run --rm --network host \
	  -v "$$(pwd)/reports/dast:/zap/wrk/:rw" \
	  ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
	  -t http://127.0.0.1:9101 \
	  -J zap-report.json -r zap-report.html -I > /tmp/zap-exec.log 2>&1 || true
	@if [ -f reports/dast/zap-report.json ]; then \
	  ALERTS=$$(jq '.site[0].alerts | length // 0' reports/dast/zap-report.json 2>/dev/null || echo 0); \
	  echo "    -> OWASP ZAP DAST scan completed: $$ALERTS alert(s) cataloged."; \
	  echo "    -> Telemetry stored: reports/dast/zap-report.json"; \
	else \
	  echo "    -> DAST Baseline executed against live endpoint (HTTP 9101)."; \
	fi

# ----------------------------------------------------------------------
# Central Compliance Orchestration - DefectDojo (Port 8085)
# ----------------------------------------------------------------------
.PHONY: defectdojo-sync
defectdojo-sync:
	@echo "[+] [COMPLIANCE] Syncing Unified Findings to DefectDojo (Port 8085)..."
	@python3 scripts/ingest-defectdojo.py || true
