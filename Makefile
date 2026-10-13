.PHONY: deploy-soc-pipeline test lint status-report

# TODO(phase-1): flesh out real targets as each phase lands
deploy-soc-pipeline:
	python3 scripts/deploy-soc-demo.py

test:
	@echo "TODO: wire forge test + hardhat test + pytest (incl. test/forensics, test/consensus_security, test/wallet_security, test/compliance, test/reporting)"

lint:
	@echo "TODO: wire slither + mythril + eslint"

status-report:
	npm run report
