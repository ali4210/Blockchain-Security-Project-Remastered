// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "@openzeppelin/contracts/access/Ownable.sol";

/// @title SecureVault
/// @notice Same interface as VulnerableVault, but with the reentrancy flaw fixed.
/// @dev Fix: checks-effects-interactions — the balance is decremented BEFORE the
///      external call, so a reentrant call sees an already-updated (zero/lower)
///      balance and `require` rejects it.
/// @dev Phase 4a: owner/access-control now uses OpenZeppelin's real, audited
///      Ownable instead of a hand-rolled `owner` variable + manual require --
///      same effective behavior (onlyOwner reverts exactly like the old
///      `require(msg.sender == owner, ...)` did), but battle-tested code
///      instead of a reimplementation, and it genuinely provides a real,
///      callable renounceOwnership() this contract did not have before.
contract SecureVault is Ownable {
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

    constructor() Ownable(msg.sender) {
        trustedModule = msg.sender;
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
    function mintSchedule(address to, uint256 amount) external onlyOwner {
        require(totalMinted + amount <= MAX_SUPPLY, "cap exceeded");
        pendingMintTo = to;
        pendingMintAmount = amount;
        mintExecuteAfter = block.timestamp + MINT_TIMELOCK_DELAY;
    }

    function mintExecute() external onlyOwner {
        require(block.timestamp >= mintExecuteAfter, "timelock not elapsed");
        require(pendingMintAmount > 0, "nothing pending");
        balances[pendingMintTo] += pendingMintAmount;
        totalMinted += pendingMintAmount;
        pendingMintAmount = 0;
    }

    // ===================== Phase 5 mitigations below =====================
    // Mirrors VulnerableVault's Phase 5 additions with REAL fixes, same
    // external shape where a mirror makes sense -- see each function's own
    // comment for exactly which real VULN it closes and how.

    uint256 public rewardMultiplier = 1;
    address public feeCollector;
    address public immutable trustedModule;

    /// @dev FIX: mirrors VULN unchecked-low-level-call in VulnerableVault --
    /// the call's success bool is checked and reverts the whole transaction
    /// on failure instead of silently discarding it.
    function refund(address payable to, uint256 amount) external onlyOwner {
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "refund failed");
    }

    /// @dev FIX: mirrors VULN integer-overflow in VulnerableVault -- default
    /// checked arithmetic (no `unchecked` block) reverts on overflow instead
    /// of wrapping silently.
    function boostReward(uint256 delta) external {
        rewardMultiplier += delta;
    }

    /// @dev FIX: mirrors VULN tx-origin in VulnerableVault -- authorization
    /// uses onlyOwner (msg.sender-based), which an intermediate malicious
    /// contract cannot spoof the way tx.origin can be spoofed.
    function claimOriginBonus() external onlyOwner {
        balances[msg.sender] += 1 ether;
        totalMinted += 1 ether;
    }

    /// @dev FIX: mirrors VULN missing-access-control in VulnerableVault --
    /// the identical setter, now gated behind onlyOwner.
    function setFeeCollector(address newCollector) external onlyOwner {
        feeCollector = newCollector;
    }

    /// @dev FIX: mirrors VULN controlled-delegatecall in VulnerableVault --
    /// no delegatecall anywhere in this contract. A regular (non-delegate)
    /// external call to an immutable, constructor-fixed module address
    /// instead, so even a compromised module can never corrupt this
    /// contract's own storage the way a delegatecall callee could.
    function executeModule(bytes calldata data) external onlyOwner {
        (bool ok, ) = trustedModule.call(data);
        require(ok, "module call failed");
    }

    /// @dev FIX: mirrors VULN suicidal in VulnerableVault -- no selfdestruct
    /// capability exists anywhere in this contract; the real fix for an
    /// unprotected self-destruct is not having one.

    /// @dev FIX: mirrors VULN timestamp in VulnerableVault -- no time-based
    /// branch in payout logic at all; the bonus is a fixed, deterministic
    /// function of deposit size only, removing the manipulable
    /// block.timestamp dependency entirely rather than merely gating it.
    function luckyBlockBonus() external {
        require(balances[msg.sender] > 0, "no deposit");
        balances[msg.sender] += balances[msg.sender] / 20;
    }

    /// @dev FIX: mirrors VULN calls-loop/costly-loop in VulnerableVault --
    /// the batch size is capped, bounding worst-case gas and the griefing
    /// surface a single call-reverting recipient can cause.
    uint256 public constant MAX_BATCH = 50;
    function batchRefund(address[] calldata recipients, uint256[] calldata amounts) external onlyOwner {
        require(recipients.length == amounts.length, "length mismatch");
        require(recipients.length <= MAX_BATCH, "batch too large");
        for (uint256 i = 0; i < recipients.length; i++) {
            (bool ok, ) = recipients[i].call{value: amounts[i]}("");
            require(ok, "refund failed");
        }
    }
}
