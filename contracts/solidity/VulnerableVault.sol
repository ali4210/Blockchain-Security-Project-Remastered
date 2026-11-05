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

    // ===================== Phase 5 additions below =====================
    // Part 0 (EduQual L6 Topic 124 audit, 2026-10-31): a comprehensive,
    // multi-class vulnerability set so every static/symbolic scanner phase
    // in the live pipeline gets real, non-trivial signal, not just the
    // reentrancy + flash-loan + rug-pull surface above. Each function below
    // is isolated to exactly one real SWC/Slither class and does not alter
    // the behavior of deposit()/withdraw()/balances or any function above
    // this line -- those stay byte-for-byte identical (AVS consensus, both
    // Echidna harnesses, and the sast-canary differential all depend on
    // their exact existing semantics).

    uint256 public rewardMultiplier = 1;
    address public feeCollector;

    /// @dev VULN: unchecked-low-level-call (SWC-104) -- the external call's
    /// success bool is discarded; a failed refund silently "succeeds" from
    /// the caller's point of view.
    function refund(address payable to, uint256 amount) external {
        require(msg.sender == owner, "not owner");
        to.call{value: amount}("");
    }

    /// @dev VULN: integer-overflow (SWC-101) -- an explicit `unchecked` block
    /// opts out of 0.8.x's default checked arithmetic, so this can wrap
    /// silently back to a tiny value instead of reverting.
    function boostReward(uint256 delta) external {
        unchecked {
            rewardMultiplier += delta;
        }
    }

    /// @dev VULN: tx-origin (SWC-115) -- authorization uses tx.origin, which
    /// a malicious intermediate contract can spoof by getting `owner` to
    /// call through it; msg.sender would not be fooled the same way.
    function claimOriginBonus() external {
        require(tx.origin == owner, "not owner");
        balances[tx.origin] += 1 ether;
        totalMinted += 1 ether;
    }

    /// @dev VULN: missing-access-control (SWC-105-adjacent) -- a privileged-
    /// looking administrative setter with NO modifier and NO require check
    /// of any kind; any address can call this.
    function setFeeCollector(address newCollector) external {
        feeCollector = newCollector;
    }

    /// @dev VULN: controlled-delegatecall (SWC-112) -- `module` is a caller-
    /// supplied, unvalidated address; delegatecall executes the callee's
    /// code in THIS contract's own storage context, so an untrusted module
    /// can overwrite any state variable here (owner, balances, anything).
    function executeModule(address module, bytes calldata data) external {
        require(msg.sender == owner, "not owner");
        (bool ok, ) = module.delegatecall(data);
        require(ok, "module call failed");
    }

    /// @dev VULN: suicidal (SWC-106) -- selfdestruct is reachable with no
    /// access control at all; any address can permanently destroy this
    /// contract and redirect its remaining ETH.
    function closeVault(address payable recipient) external {
        selfdestruct(recipient);
    }

    /// @dev VULN: timestamp (SWC-116) -- critical payout logic branches on
    /// block.timestamp, which a miner/validator has some latitude to
    /// manipulate, making the "bonus" outcome gameable.
    function luckyBlockBonus() external {
        require(balances[msg.sender] > 0, "no deposit");
        if (block.timestamp % 2 == 0) {
            balances[msg.sender] += balances[msg.sender] / 10;
        }
    }

    /// @dev VULN: calls-loop / costly-loop -- iterates an unbounded, caller-
    /// controlled array with an external call per iteration: a gas-griefing
    /// and DoS surface (one bad recipient can block the whole batch; a long
    /// enough array can exceed the block gas limit entirely).
    function batchRefund(address[] calldata recipients, uint256[] calldata amounts) external {
        require(msg.sender == owner, "not owner");
        for (uint256 i = 0; i < recipients.length; i++) {
            (bool ok, ) = recipients[i].call{value: amounts[i]}("");
            require(ok, "refund failed");
        }
    }
}
