const VerifiablePresentationStore = artifacts.require("VerifiablePresentationStore");

module.exports = function(deployer) {
    deployer.deploy(VerifiablePresentationStore);
};
