// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "../../contracts/solidity/SecureVault.sol";

// Section F (EduQual L6 Topic 124) -- Echidna property-based fuzz harness.
// Wraps the real, unmodified SecureVault.sol and exposes fuzzable entry
// points plus an insolvency-style invariant. Reuses the same reentrant
// receive() pattern as src/consensus/exploit_harness/ReentrancyAttacker.sol
// (used by avs_consensus.py for a real execution-trace proof) so Echidna's
// own fuzzer can genuinely trigger the reentrancy, not just call functions in
// isolation. Test-only harness: never deploy or fund for real.
contract SecureVaultEchidnaHarness {
    SecureVault public vault;
    uint256 public unit;
    uint256 public reentrantWithdrawCount;

    constructor() {
        vault = new SecureVault();
    }

    function fuzzDeposit() public payable {
        vault.deposit{value: msg.value}();
    }

    // Deposit-then-withdraw with a reentrant receive() hook, same shape as
    // ReentrancyAttacker.sol's attack(), so Echidna's fuzzer can genuinely
    // exercise the bug rather than just calling functions independently.
    function fuzzAttack(uint256 amount) public payable {
        unit = msg.value;
        vault.deposit{value: msg.value}();
        if (amount > 0 && amount <= unit) {
            vault.withdraw(amount);
        }
    }

    receive() external payable {
        if (address(vault).balance >= unit && unit > 0) {
            reentrantWithdrawCount += 1;
            vault.withdraw(unit);
        }
    }

    // Invariant 1: this harness's own recorded balance inside the vault can
    // never exceed what the vault contract actually, truly holds in ETH.
    function echidna_internal_balance_never_exceeds_contract_eth() public view returns (bool) {
        return vault.balances(address(this)) <= address(vault).balance;
    }

    // Invariant 2: withdraw() should never be re-entered at all -- this is the
    // direct, structural proof of the CEI flaw (external call before state
    // update), independent of whether a reverting checked-math underflow
    // happens to erase the symptom from a pure balance-invariant's point of view.
    function echidna_withdraw_never_reentered() public view returns (bool) {
        return reentrantWithdrawCount == 0;
    }
}
