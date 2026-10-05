module.exports = {
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
    tests: "./test/hardhat",
    cache: "./cache/hardhat",
    artifacts: "./artifacts/hardhat",
  },
};
