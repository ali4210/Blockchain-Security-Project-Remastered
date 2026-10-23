// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @title RandomTestVault
/// @notice Intentionally vulnerable local coursework fixture. Never deploy or fund.
/// @dev Deliberately a DIFFERENT vulnerability class from VulnerableVault.sol's
/// reentrancy bug: this contract has an unprotected privileged function with no
/// access control, letting any caller drain the full contract balance to an
/// address of their choosing (Slither's arbitrary-send-eth / OWASP SC02).
contract RandomTestVault {
    address public owner;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    /// @dev Deliberately vulnerable: this function is meant to be an
    /// owner-only emergency withdrawal, but has no access control at all --
    /// any caller can drain the entire contract balance to any address.
    function withdrawAll(address payable to) external {
        to.transfer(address(this).balance);
    }
}
