const Migrations = artifacts.require("Migrations");
const LoanApplication = artifacts.require("LoanApplication");
module.exports = async function (deployer) {
  await deployer.deploy(Migrations);
  await deployer.deploy(LoanApplication);
  
};
