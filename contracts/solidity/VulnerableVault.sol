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

    // ===================== Additive fixtures below =====================
    // Everything above this line is untouched: deposit()/withdraw() and the
    // balances mapping keep their exact existing byte-for-byte behaviour.
    // Everything below is new surface for Sections B/C (EduQual L6 Topic 124)
    // -- genuinely detectable by src/defi/flashloan_detector.py and
    // rugpull_detector.py's actual real AST heuristics, not just vulnerable
    // in spirit. See each function's own comment for exactly which real
    // check it trips and why.

    address public owner;
    uint256 public totalMinted;
    uint256 public reserve0 = 1 ether;
    uint256 public reserve1 = 1 ether;

    constructor() {
        owner = msg.sender;
    }

    /// @dev Minimal, self-contained ERC20-shaped transfer-in used by flashSwap()
    /// below -- real callable logic against the existing `balances` ledger, not
    /// a decorative stub. No external token contract needed.
    function transferFrom(address from, address to, uint256 amount) public returns (bool) {
        require(balances[from] >= amount, "insufficient balance");
        balances[from] -= amount;
        balances[to] += amount;
        return true;
    }

    /// @dev Minimal, self-contained ERC20-shaped transfer-out used by
    /// flashSwap() below.
    function transfer(address to, uint256 amount) public returns (bool) {
        balances[msg.sender] -= amount;
        balances[to] += amount;
        return true;
    }

    /// @dev The vault's own instantaneous reserve ratio -- no TWAP, no
    /// staleness window, no same-block guard. Read live, in the same
    /// transaction as flashSwap() both manipulates and consumes it.
    function getReserves() public view returns (uint256, uint256) {
        return (reserve0, reserve1);
    }

    /// @dev Genuinely flash-loan-shaped (Section B), not an approximation:
    /// within ONE transaction this (a) pulls a large value-bearing amount in
    /// via transferFrom, (b) reads the vault's own live, manipulable reserve
    /// ratio via getReserves() with no TWAP/staleness/same-block guard, and
    /// (c) pays out based on that freshly-read ratio via transfer(), before
    /// returning. An attacker can inflate reserve0 in the very same call
    /// (see the line below) and immediately get paid out at the
    /// self-manipulated rate -- classic atomic borrow/manipulate/profit/repay.
    /// This is exactly the real pattern src/defi/flashloan_detector.py's
    /// analyze_contract() checks for: transfer-in + oracle/reserve read +
    /// transfer-out, all in one function body.
    function flashSwap(uint256 amountIn) external {
        transferFrom(msg.sender, address(this), amountIn);
        (uint256 r0, uint256 r1) = getReserves();
        reserve0 += amountIn; // same-transaction reserve manipulation -- no delay, no guard
        uint256 payout = (amountIn * r1) / r0;
        transfer(msg.sender, payout);
    }

    /// @dev Genuinely rug-pull-shaped (Section C): owner-gated minting with
    /// NO supply cap, NO timelock on the privilege, and NO renouncement path
    /// anywhere in this contract. unrestricted_mint correctly PASSES (mint
    /// genuinely IS access-controlled -- that check's narrow definition is
    /// satisfied); missing_ownership_protection correctly FAILS: the real
    /// danger here isn't that anyone can mint, it's that the owner's power
    /// over supply is absolute and permanent -- the single most common
    /// real-world rug-pull governance pattern.
    function mint(address to, uint256 amount) external {
        require(msg.sender == owner, "not owner");
        balances[to] += amount;
        totalMinted += amount;
    }

    /// @dev Genuinely rug-pull-shaped (Section C): an owner-gated function
    /// that drains the ENTIRE contract balance to an address of the owner's
    /// choosing, with no liquidity-lock, vesting, or multisig/timelock gate
    /// of any kind. owner_only_withdraw_all correctly FAILS regardless of
    /// the owner check -- a single EOA able to walk away with every
    /// depositor's funds at any time is itself the classic rug-pull sweep
    /// vector this check flags, access-controlled or not.
    function emergencySweep(address payable to) external {
        require(msg.sender == owner, "not owner");
        to.transfer(address(this).balance);
    }
}
