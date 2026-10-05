// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @title VulnerableVault
/// @notice Intentionally vulnerable local coursework fixture. Never deploy or fund.
contract VulnerableVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    /// @dev Deliberately vulnerable: external interaction occurs before the balance update.
    function withdraw(uint256 amount) external {
        require(amount > 0, "amount must be positive");
        require(balances[msg.sender] >= amount, "insufficient balance");

        (bool sent, ) = msg.sender.call{value: amount}("");
        require(sent, "transfer failed");

        balances[msg.sender] -= amount;
    }
}
