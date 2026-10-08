// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "../../contracts/solidity/VulnerableVault.sol";

interface Vm {
    function deal(address account, uint256 newBalance) external;
    function prank(address caller) external;
    function expectRevert() external;
    function expectRevert(bytes calldata revertData) external;
}

contract InvariantsTest {

    struct FuzzSelector {
        address addr;
        bytes4[] selectors;
    }

    function targetContracts() public view returns (address[] memory targets) {
        targets = new address[](1);
        targets[0] = address(this);
    }

    function targetSelectors() public view returns (FuzzSelector[] memory targets) {
        bytes4[] memory selectors = new bytes4[](4);
        selectors[0] = this.depositForAlice.selector;
        selectors[1] = this.depositForBob.selector;
        selectors[2] = this.withdrawForAlice.selector;
        selectors[3] = this.withdrawForBob.selector;

        targets = new FuzzSelector[](1);
        targets[0] = FuzzSelector(address(this), selectors);
    }

    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    VulnerableVault internal vault;
    address internal alice;
    address internal bob;
    uint256 internal aliceDeposited;
    uint256 internal bobDeposited;
    uint256 internal aliceWithdrawn;
    uint256 internal bobWithdrawn;

    function setUp() public {
        vault = new VulnerableVault();
        alice = address(0xA11CE);
        bob = address(0xB0B);

        vm.deal(alice, 100 ether);
        vm.deal(bob, 100 ether);
    }

    function depositForAlice(uint96 rawAmount) public {
        uint256 amount = boundAmount(rawAmount, 1 ether);
        vm.prank(alice);
        vault.deposit{value: amount}();
        aliceDeposited += amount;
    }

    function depositForBob(uint96 rawAmount) public {
        uint256 amount = boundAmount(rawAmount, 1 ether);
        vm.prank(bob);
        vault.deposit{value: amount}();
        bobDeposited += amount;
    }

    function withdrawForAlice(uint96 rawAmount) public {
        uint256 available = vault.balances(alice);
        if (available == 0) return;
        uint256 amount = uint256(rawAmount) % available + 1;
        vm.prank(alice);
        vault.withdraw(amount);
        aliceWithdrawn += amount;
    }

    function withdrawForBob(uint96 rawAmount) public {
        uint256 available = vault.balances(bob);
        if (available == 0) return;
        uint256 amount = uint256(rawAmount) % available + 1;
        vm.prank(bob);
        vault.withdraw(amount);
        bobWithdrawn += amount;
    }

    function testRejectsZeroAndInsufficientWithdrawalsWithoutStateChange() public {
        vm.prank(alice);
        vault.deposit{value: 5 ether}();

        uint256 vaultBefore = address(vault).balance;
        uint256 ledgerBefore = vault.balances(alice);

        vm.expectRevert();
        vm.prank(alice);
        vault.withdraw(0);

        require(address(vault).balance == vaultBefore, "zero withdrawal changed vault");
        require(vault.balances(alice) == ledgerBefore, "zero withdrawal changed ledger");

        vm.expectRevert();
        vm.prank(alice);
        vault.withdraw(ledgerBefore + 1);

        require(address(vault).balance == vaultBefore, "insufficient withdrawal changed vault");
        require(vault.balances(alice) == ledgerBefore, "insufficient withdrawal changed ledger");
    }

    function invariant_ledgerMatchesSuccessfulSingleUserAccounting() public view {
        require(
            vault.balances(alice) == aliceDeposited - aliceWithdrawn,
            "alice ledger mismatch"
        );
        require(
            vault.balances(bob) == bobDeposited - bobWithdrawn,
            "bob ledger mismatch"
        );
    }

    function invariant_vaultBalanceMatchesTrackedLedger() public view {
        require(
            address(vault).balance == vault.balances(alice) + vault.balances(bob),
            "vault balance mismatch"
        );
    }

    function boundAmount(uint96 rawAmount, uint256 cap) internal pure returns (uint256) {
        return uint256(rawAmount) % cap + 1;
    }
}
