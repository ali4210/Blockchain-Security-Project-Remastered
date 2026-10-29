// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

// TEST FIXTURE ONLY -- Section B (flashloan_detector.py) verification.
// NOT a pipeline target: not registered in scripts/ingest-manifests.mts's
// EXPECTED_FILE_HASHES/EXPECTED_ASSET_MAP, not deployed, not scanned by the
// live SOC pipeline. Written solely to prove flashloan_detector.py's
// heuristics genuinely trigger on a real flash-loan + front-running shaped
// contract, as a deliberately vulnerable, clearly-labelled synthetic sample.

interface IERC20Like {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
}

interface IPriceOracleLike {
    function getReserves() external view returns (uint256 reserve0, uint256 reserve1);
}

contract VulnerableFlashLoanFixture {
    IERC20Like public token;
    IPriceOracleLike public oracle;

    constructor(address _token, address _oracle) {
        token = IERC20Like(_token);
        oracle = IPriceOracleLike(_oracle);
    }

    // Flash-loan attack shape: (a) receives a large transfer in, (b) reads
    // oracle/reserve state within the same call, (c) repays before return --
    // all three in one transaction, the classic borrow/manipulate/repay pattern.
    function flashBorrowAndArbitrage(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        (uint256 reserve0, uint256 reserve1) = oracle.getReserves();
        uint256 price = reserve1 / reserve0;
        uint256 repayAmount = amount + (amount * price) / 10000;
        token.transfer(msg.sender, repayAmount);
    }

    // Front-running exposure: price-sensitive swap with no deadline or
    // minimum-output/slippage-bound parameter, and no commit-reveal pair.
    function swapExactTokensForTokens(uint256 amountIn, address tokenOut) external returns (uint256 amountOut) {
        (uint256 reserve0, uint256 reserve1) = oracle.getReserves();
        amountOut = (amountIn * reserve1) / reserve0;
        token.transfer(tokenOut, amountOut);
        return amountOut;
    }
}
