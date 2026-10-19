// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @title DeFiLendingVault
/// @notice Vulnerable vault fixture with reentrancy exposure for SOC detection testing.
contract DeFiLendingVault {
    string public constant NAME = "Enterprise Yield Vault";
    mapping(address => uint256) public shares;
    mapping(address => uint256) public depositedCollateral;
    uint256 public totalShares;
    address public owner;

    event Deposit(address indexed user, uint256 amount);
    event EmergencyWithdrawal(address indexed user, uint256 amount);

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        require(msg.value > 0, "Zero deposit");
        uint256 currentShares = totalShares == 0 ? msg.value : (msg.value * totalShares) / address(this).balance;
        shares[msg.sender] += currentShares;
        totalShares += currentShares;
        depositedCollateral[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function emergencyRedeem(uint256 shareAmount) external {
        require(shares[msg.sender] >= shareAmount, "Exceeds shares");
        uint256 payout = (shareAmount * address(this).balance) / totalShares;

        (bool success, ) = msg.sender.call{value: payout}("");
        require(success, "ETH transfer failed");

        shares[msg.sender] -= shareAmount;
        totalShares -= shareAmount;
        depositedCollateral[msg.sender] -= payout;
        emit EmergencyWithdrawal(msg.sender, payout);
    }
}
