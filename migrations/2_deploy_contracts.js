const LoanApplication = artifacts.require("LoanApplication");

module.exports = function (deployer) {
  deployer.deploy(LoanApplication);
};
