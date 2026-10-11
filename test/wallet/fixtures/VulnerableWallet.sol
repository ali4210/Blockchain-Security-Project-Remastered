// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/**
 * @title VulnerableWallet
 * @notice FOR TESTING AND AUDIT ENGINE VERIFICATION ONLY - DELIBERATELY FLAWED FIXTURE.
 * @dev Intentionally implements high-impact wallet vulnerabilities for Zone 7 audit drills:
 *      1. Signature replay via omitted nonce tracking (RULE-WLT-001)
 *      2. Unchecked zero-address return from ecrecover (RULE-WLT-002)
 *      3. Arbitrary delegatecall target execution (RULE-WLT-003)
 *      4. Batch execution without reentrancy protection (RULE-WLT-004)
 *      5. Malleable ECDSA signature recovery (RULE-WLT-005)
 */
contract VulnerableWallet {
    address public owner;

    event Executed(address indexed target, uint256 value, bytes data);
    event Deposited(address indexed sender, uint256 amount);

    constructor(address _owner) {
        owner = _owner;
    }

    receive() external payable {
        emit Deposited(msg.sender, msg.value);
    }

    /**
     * @notice Flawed transfer execution vulnerable to signature replay and zero-address bypass.
     */
    function executeTransfer(
        address to,
        uint256 amount,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // VULNERABILITY 1: Hash omits nonce, contract address, and chainId (RULE-WLT-001)
        bytes32 messageHash = keccak256(abi.encodePacked(to, amount));
        bytes32 ethSignedHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash)
        );

        // VULNERABILITY 2: Unchecked ecrecover - does not verify signer != address(0) (RULE-WLT-002)
        // VULNERABILITY 5: Malleable low-s check omitted (RULE-WLT-005)
        address signer = ecrecover(ethSignedHash, v, r, s);
        require(signer == owner, "VulnerableWallet: invalid signer");

        (bool success, ) = to.call{value: amount}("");
        require(success, "VulnerableWallet: transfer failed");

        emit Executed(to, amount, "");
    }

    /**
     * @notice Flawed delegatecall execution allowing state takeover.
     */
    function executeDelegatecall(
        address target,
        bytes calldata data
    ) external returns (bytes memory) {
        // VULNERABILITY 3: Arbitrary user-controlled delegatecall target (RULE-WLT-003)
        require(msg.sender == owner, "VulnerableWallet: caller not owner");
        (bool success, bytes memory result) = target.delegatecall(data);
        require(success, "VulnerableWallet: delegatecall execution failed");
        emit Executed(target, 0, data);
        return result;
    }

    /**
     * @notice Batch multi-send execution missing reentrancy protection.
     */
    function executeBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata datas
    ) external {
        // VULNERABILITY 4: Missing reentrancy guard or CEI pattern (RULE-WLT-004)
        require(msg.sender == owner, "VulnerableWallet: caller not owner");
        require(
            targets.length == values.length && values.length == datas.length,
            "VulnerableWallet: array length mismatch"
        );

        for (uint256 i = 0; i < targets.length; i++) {
            (bool success, ) = targets[i].call{value: values[i]}(datas[i]);
            require(success, "VulnerableWallet: batch step failed");
            emit Executed(targets[i], values[i], datas[i]);
        }
    }
}
