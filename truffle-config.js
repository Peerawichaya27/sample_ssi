const HDWalletProvider = require('@truffle/hdwallet-provider');

module.exports = {
    networks: {
        development: {
            host: "127.0.0.1",     // Localhost
            port: 8545,            // Ganache port
            network_id: "*",       // Any network
        },
    },
    compilers: {
        solc: {
            version: "0.8.13" // Specify the version of Solidity
        }
    }
};
