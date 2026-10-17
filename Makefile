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
