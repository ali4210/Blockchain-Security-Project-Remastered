// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @title SecureVault
/// @notice Same interface as VulnerableVault, but with the reentrancy flaw fixed.
/// @dev Fix: checks-effects-interactions — the balance is decremented BEFORE the
///      external call, so a reentrant call sees an already-updated (zero/lower)
///      balance and `require` rejects it. No external imports needed for this.
contract SecureVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    /// @dev Secure ordering: effects (state update) happen before interactions
    ///      (the external call), closing the reentrancy window VulnerableVault has.
    function withdraw(uint256 amount) external {
        require(amount > 0, "amount must be positive");
        require(balances[msg.sender] >= amount, "insufficient balance");

        balances[msg.sender] -= amount;

        (bool sent, ) = msg.sender.call{value: amount}("");
        require(sent, "transfer failed");
    }
}
