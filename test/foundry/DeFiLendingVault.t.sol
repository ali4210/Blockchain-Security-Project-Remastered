// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "../../contracts/solidity/DeFiLendingVault.sol";
import "../../contracts/solidity/SecureVault.sol";

interface Vm {
    function deal(address account, uint256 newBalance) external;
    function prank(address newSender) external;
    function expectRevert(bytes calldata revertData) external;
}

contract DeFiLendingVaultTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    DeFiLendingVault public vulnerableVault;
    SecureVault public secureVault;
    address public user1 = address(0x1111);
    address public user2 = address(0x2222);

    function setUp() public {
        vulnerableVault = new DeFiLendingVault();
        secureVault = new SecureVault();

        vm.deal(user1, 10 ether);
        vm.deal(user2, 10 ether);
    }

    function test_SecureVault_Deposit() public {
        vm.prank(user1);
        secureVault.deposit{value: 2 ether}();
        require(secureVault.getBalance(user1) == 2 ether, "Deposit balance mismatch");
    }

    function test_SecureVault_Withdraw_Valid() public {
        vm.prank(user1);
        secureVault.deposit{value: 2 ether}();

        vm.prank(user1);
        secureVault.withdraw(1 ether);
        require(secureVault.getBalance(user1) == 1 ether, "Withdraw balance mismatch");
    }

    function test_SecureVault_Revert_InsufficientBalance() public {
        vm.prank(user1);
        secureVault.deposit{value: 1 ether}();

        vm.prank(user1);
        vm.expectRevert("Insufficient balance");
        secureVault.withdraw(2 ether);
    }

    receive() external payable {}
}
