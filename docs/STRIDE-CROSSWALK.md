# STRIDE Threat-Model Crosswalk

Generated automatically from `config/stride-coverage-map.json` by `scripts/verify-stride-coverage.mts` on every pipeline run. This document and the live HTML report's "STRIDE Coverage Scorecard" section are rendered from the exact same source file and cannot drift apart. Do not hand-edit this file -- edit the JSON map instead.

## Spoofing

| File:Line | Description |
|---|---|
| `src/compliance/address_screener.py:145` | AddressScreener.screen() -- real OFAC SDN sanctioned-identity screening. Wired, Zone 3 (ofac-screening scanner, runs every cycle). |
| `contracts/solidity/VulnerableVault.sol:146` | claimOriginBonus() authorizes via tx.origin (SWC-115): an attacker's intermediate contract can spoof the legitimate caller's identity. Fixed at contracts/solidity/SecureVault.sol:145 with onlyOwner. |

## Tampering

| File:Line | Description |
|---|---|
| `scripts/run-sast-symbolic.py:254` | Live check that Slither's reentrancy-eth detector actually fired this run -- unauthorized state tampering via reentrant calls. Wired, Zone 2 SAST. |
| `test/echidna/VaultEchidnaHarness.sol:54` | echidna_withdraw_never_reentered() -- wired Echidna invariant, genuinely falsified with a real counterexample on VulnerableVault. |

## Repudiation

| File:Line | Description |
|---|---|
| `scripts/pipeline-verdict.py:196` | Writes the immutable, timestamped reports/verdict.json audit trail (halt_reasons, contract_halt_reasons, generated_at) every run. Wired, always runs. |
| `src/incident/jira_dispatcher.py:77` | dispatch_sev1_ticket() -- creates a permanent, timestamped external Jira record of exactly what was detected and when. Wired via run-incident-abort.py on the HALT path. |

## Information Disclosure

| File:Line | Description |
|---|---|
| `scripts/run-secret-scan.sh:23` | Real `gitleaks detect` invocation scanning committed source for disclosed secrets/credentials. Wired, Zone 1, always runs. |
| `scripts/run-zk-attestation.py:150` | Attestation report object constructed here; the private witness (blinding factors) is never included in it -- see this file's own HONEST SCOPE docstring. Wired, Zone 3. |

## Denial of Service

| File:Line | Description |
|---|---|
| `contracts/solidity/VulnerableVault.sol:190` | batchRefund() has an unbounded loop with no cap on recipients.length (gas-griefing DoS). Flagged live by Slither's calls-loop check. |
| `contracts/solidity/SecureVault.sol:182` | MAX_BATCH = 50 -- the real fix capping batchRefund()'s loop bound. |

## Elevation of Privilege

| File:Line | Description |
|---|---|
| `src/defi/rugpull_detector.py:108` | check_ownership_protection() -- wired, Zone 2/3 rugpull detector, flags privileged functions with no ownership protection (missing_ownership_protection=fail confirmed live). |
| `contracts/solidity/VulnerableVault.sol:155` | setFeeCollector() has zero access control -- the real example the above check flags. |

