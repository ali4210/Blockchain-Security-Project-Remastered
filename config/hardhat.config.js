import { defineConfig } from "hardhat/config";
import hardhatToolboxMochaEthers from "@nomicfoundation/hardhat-toolbox-mocha-ethers";

export default defineConfig({
  plugins: [hardhatToolboxMochaEthers],
  solidity: {
    version: "0.8.24",
    settings: {
      optimizer: {
        enabled: false,
        runs: 200,
      },
    },
  },
  paths: {
    sources: "./contracts/solidity",
    tests: {
      mocha: "./test/hardhat",
      // test/foundry holds this project's real Foundry test suite (run
      // separately via `forge test`, incompatible with Hardhat's compiler
      // as native Solidity tests). Redirecting Hardhat's native
      // Solidity-test discovery away from test/ entirely (default behavior
      // scans the whole test/ dir) so it never tries to compile test/foundry.
      solidity: "./test/hardhat-solidity-tests",
    },
    cache: "./cache/hardhat",
    artifacts: "./artifacts/hardhat",
  },
});
