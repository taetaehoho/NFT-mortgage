const LoanApplication = artifacts.require("LoanApplication");

/*
 * uncomment accounts to access the test accounts made available by the
 * Ethereum client
 * See docs: https://www.trufflesuite.com/docs/truffle/testing/writing-tests-in-javascript
 */
contract("LoanApplication", function (/* accounts */) {
  it("should assert true", async function () {
    await LoanApplication.deployed();
    return assert.isTrue(true);
  });
});
