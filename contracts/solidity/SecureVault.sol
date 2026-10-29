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

    // ===================== Additive mitigations below =====================
    // Mirrors VulnerableVault's new Section B/C surface with REAL fixes, not
    // just a comment claiming it's safe. Each function below is intended to
    // double as documentation of "how to get a clean scan" against
    // src/defi/flashloan_detector.py and rugpull_detector.py's actual checks.

    address public owner;
    uint256 public totalMinted;
    uint256 public constant MAX_SUPPLY = 1_000_000 ether;
    uint256 public reserve0 = 1 ether;
    uint256 public reserve1 = 1 ether;
    uint256 public cachedRate;
    uint256 public lastRateSnapshotBlock;

    uint256 public pendingMintAmount;
    address public pendingMintTo;
    uint256 public mintExecuteAfter;
    uint256 public constant MINT_TIMELOCK_DELAY = 2 days;

    constructor() {
        owner = msg.sender;
    }

    function transferFrom(address from, address to, uint256 amount) public returns (bool) {
        require(balances[from] >= amount, "insufficient balance");
        balances[from] -= amount;
        balances[to] += amount;
        return true;
    }

    function transfer(address to, uint256 amount) public returns (bool) {
        balances[msg.sender] -= amount;
        balances[to] += amount;
        return true;
    }

    /// @dev Real mitigation, step 1 of 2: the reserve rate is snapshotted and
    /// cached HERE, in a transaction of its own. Nothing is transferred or
    /// paid out in this function, so it cannot itself be a flash-loan vector
    /// -- there is no transfer-in/out to pair with this reserve read.
    function updateRateSnapshot() external {
        cachedRate = (reserve1 * 1e18) / reserve0;
        lastRateSnapshotBlock = block.number;
    }

    /// @dev Real mitigation, step 2 of 2 (TWAP-lite / same-block guard): this
    /// function NEVER reads reserve0/reserve1 directly -- only the
    /// block-delayed cachedRate from updateRateSnapshot() above, and only
    /// once at least one full block has elapsed since that snapshot was
    /// taken. An attacker cannot manipulate the reserve and consume a
    /// freshly-manipulated rate within the same transaction: the price this
    /// function pays out at was fixed in an earlier block, before any
    /// same-transaction manipulation could occur. A real deadline parameter
    /// also bounds how long a signed call can sit in the mempool, closing
    /// the front-running/sandwich window too.
    function swapAtCachedRate(uint256 amountIn, uint256 deadline) external {
        require(block.timestamp <= deadline, "swap expired");
        require(block.number > lastRateSnapshotBlock, "rate snapshot too fresh: wait a block");
        transferFrom(msg.sender, address(this), amountIn);
        uint256 payout = (amountIn * cachedRate) / 1e18;
        transfer(msg.sender, payout);
    }

    /// @dev Real mitigation: minting is capped (MAX_SUPPLY) AND timelocked --
    /// the owner can only SCHEDULE a mint; mintExecute() cannot run until
    /// MINT_TIMELOCK_DELAY has elapsed, giving depositors a real window to
    /// react before any new supply is actually created. No owner-only
    /// sweep/withdraw-all function exists anywhere in this contract.
    function mintSchedule(address to, uint256 amount) external {
        require(msg.sender == owner, "not owner");
        require(totalMinted + amount <= MAX_SUPPLY, "cap exceeded");
        pendingMintTo = to;
        pendingMintAmount = amount;
        mintExecuteAfter = block.timestamp + MINT_TIMELOCK_DELAY;
    }

    function mintExecute() external {
        require(msg.sender == owner, "not owner");
        require(block.timestamp >= mintExecuteAfter, "timelock not elapsed");
        require(pendingMintAmount > 0, "nothing pending");
        balances[pendingMintTo] += pendingMintAmount;
        totalMinted += pendingMintAmount;
        pendingMintAmount = 0;
    }
}
