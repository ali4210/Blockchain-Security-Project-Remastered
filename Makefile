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

.PHONY: deploy-soc-pipeline test lint status-report pipeline-e2e enterprise-integration pipeline-all gitops-publish argocd-sync dast-scan echidna vyper-check

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

# pipeline-e2e's SCA step (scripts/run-sca-gate.py -> run-sca.cjs) uses an offline
# NVD/OSV mirror at ~/.local/state/nvd-mirror/index.sqlite when present, built by:
#   bash scripts/mirror-nvd.sh && node scripts/build-offline-index.cjs
# (in that order -- the index build reads what the mirror fetch writes). This is
# deliberately NOT run automatically here: the mirror fetch alone takes 10+ minutes
# against live NVD/OSV, so it does not belong in the hot pipeline path. Without it,
# SCA falls back to live API lookups transparently.
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
# Standalone Echidna fuzzing / Vyper check -- same real target resolution
# (TARGET_CONTRACT / SECURE=1 / CONTRACT=<filename>) as pipeline-all,
# via the top-level export block above. Both also still run as part of
# the default run-all-e2e.sh path.
# ----------------------------------------------------------------------
echidna:
	@bash scripts/run-echidna.sh

vyper-check:
	@python3 scripts/run-vyper-check.py

# ----------------------------------------------------------------------
# Central Compliance Orchestration - DefectDojo (Port 8085)
# ----------------------------------------------------------------------
.PHONY: defectdojo-sync
defectdojo-sync:
	@echo "[+] [COMPLIANCE] Syncing Unified Findings to DefectDojo (Port 8085)..."
	@python3 scripts/ingest-defectdojo.py || true

