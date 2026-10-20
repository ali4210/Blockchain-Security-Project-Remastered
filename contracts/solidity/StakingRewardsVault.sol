// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/**
 * @title StakingRewardsVault
 * @notice Realistic staking and yield reward distributor modeled after historic DeFi staking vulnerabilities.
 * Exposes:
 *  - Arithmetic rounding / precision loss in reward distribution
 *  - Unchecked low-level call on rewards distribution (SWC-104)
 *  - State manipulation via premature balance settlement
 */
contract StakingRewardsVault {
    string public constant VAULT_NAME = "Apex-Staking-Pool-V2";
    address public owner;

    mapping(address => uint256) public stakedBalance;
    mapping(address => uint256) public userRewardPerTokenPaid;
    mapping(address => uint256) public rewards;

    uint256 public totalStaked;
    uint256 public rewardRate = 100; // Rewards distributed per second
    uint256 public lastUpdateTime;
    uint256 public rewardPerTokenStored;

    event Staked(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);
    event RewardPaid(address indexed user, uint256 reward);
    event EmergencyDrain(address indexed caller, uint256 amount);

    constructor() payable {
        owner = msg.sender;
        lastUpdateTime = block.timestamp;
    }

    modifier updateReward(address account) {
        if (totalStaked > 0) {
            // VULNERABILITY 1: Precision loss - integer division before multiplication
            // Can result in 0 reward increments for smaller staking pools
            rewardPerTokenStored += ((block.timestamp - lastUpdateTime) * rewardRate) / totalStaked;
        }
        lastUpdateTime = block.timestamp;

        if (account != address(0)) {
            rewards[account] += (stakedBalance[account] * (rewardPerTokenStored - userRewardPerTokenPaid[account])) / 1e18;
            userRewardPerTokenPaid[account] = rewardPerTokenStored;
        }
        _;
    }

    function stake() external payable updateReward(msg.sender) {
        require(msg.value > 0, "Cannot stake 0");
        stakedBalance[msg.sender] += msg.value;
        totalStaked += msg.value;
        emit Staked(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external updateReward(msg.sender) {
        require(amount > 0, "Cannot withdraw 0");
        require(stakedBalance[msg.sender] >= amount, "Exceeds staked balance");

        // VULNERABILITY 2: External transfer before updating totalStaked global balance
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Withdraw transfer failed");

        stakedBalance[msg.sender] -= amount;
        totalStaked -= amount;

        emit Withdrawn(msg.sender, amount);
    }

    function claimReward() external updateReward(msg.sender) {
        uint256 reward = rewards[msg.sender];
        if (reward > 0) {
            rewards[msg.sender] = 0;

            // VULNERABILITY 3: Unchecked return value on reward disbursement (SWC-104)
            msg.sender.call{value: reward}("");

            emit RewardPaid(msg.sender, reward);
        }
    }

    // VULNERABILITY 4: Missing access control on administrative sweep
    function emergencySweep(address payable recipient) external {
        uint256 balance = address(this).balance;
        recipient.transfer(balance);
        emit EmergencyDrain(recipient, balance);
    }

    receive() external payable {}
}
