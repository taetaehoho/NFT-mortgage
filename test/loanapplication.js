const loanapplication = artifacts.require("loanapplication");

/*
 * uncomment accounts to access the test accounts made available by the
 * Ethereum client
 * See docs: https://www.trufflesuite.com/docs/truffle/testing/writing-tests-in-javascript
 */
contract("loanapplication", function (/* accounts */) {
  it("should assert true", async function () {
    await loanapplication.deployed();
    return assert.isTrue(true);
  });
});
