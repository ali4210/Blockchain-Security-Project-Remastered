.PHONY: deploy-soc-pipeline test lint status-report pipeline-e2e enterprise-integration pipeline-all

# TODO(phase-1): flesh out real targets as each phase lands
deploy-soc-pipeline:
	python3 scripts/deploy-soc-demo.py

test:
	@echo "TODO: wire forge test + hardhat test + pytest (incl. test/forensics, test/consensus_security, test/wallet_security, test/compliance, test/reporting)"

lint:
	@echo "TODO: wire slither + mythril + eslint"

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
	@git add src/ test/ scripts/ config/ Makefile Jenkinsfile 2>/dev/null || true
	@if git diff-index --quiet HEAD --; then \
		echo "[*] Working tree clean: generating automated empty trigger commit..."; \
		git commit --allow-empty -m "chore(pipeline): automated unified e2e trigger $$(date +%Y%m%d_%H%M%S)"; \
	else \
		echo "[*] Staging and committing modified workspace artifacts..."; \
		git commit -m "chore(pipeline): automated unified e2e run $$(date +%Y%m%d_%H%M%S)"; \
	fi
	@echo "[*] Pushing commit to GitLab main branch..."
	@git push gitlab main
	@echo "[+] ========================================================"
	@echo "[+] UNIFIED CI/CD & AUTONOMOUS SOC COMPLETED IN LOCKSTEP"
	@echo "[+] ========================================================"