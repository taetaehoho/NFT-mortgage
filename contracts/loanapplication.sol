// SPDX-License-Identifier: GPL-3.0

pragma solidity ^0.8.10;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "./contracts/SafeMath.sol";

// File: contracts/NFTfi/v1/NFTfiSigningUtils.sol
// @title  Helper contract for NFT mortgage. This contract manages verifying signatures
//         from off-chain loan applications.
// @author @0xcesare, 0xtaetaehoho, @Jonatha26383028
contract NFTfiSigningUtils {

    /* *********** */
    /* CONSTRUCTOR */
    /* *********** */


    /* ********* */
    /* FUNCTIONS */
    /* ********* */

    // @notice OpenZeppelin's ECDSA library is used to call all ECDSA functions
    //         directly on the bytes32 variables themselves.
    using ECDSA for bytes32;
    using SafeMath for uint256;

    mapping (uint256 => Loan) public loanIdToLoan;

    struct Loan {
        // A unique identifier for this particular loan, sourced from the
        // continuously increasing parameter totalNumLoans.
        uint256 loanId;
        // The original sum of money transferred from lender to borrower at the
        // beginning of the loan, measured in loanERC20Denomination's smallest
        // units.
        uint256 loanPrincipalAmount;
        // The maximum amount of money that the borrower would be required to
        // repay retrieve their collateral, measured in loanERC20Denomination's
        // smallest units. If interestIsProRated is set to false, then the
        // borrower will always have to pay this amount to retrieve their
        // collateral, regardless of whether they repay early.
        uint256 maximumRepaymentAmount;
        // The ID within the NFTCollateralContract for the NFT being used as
        // collateral for this loan. The NFT is stored within this contract
        // during the duration of the loan.
        uint256 nftCollateralId;
        // The block.timestamp when the loan first began (measured in seconds).
        uint64 loanStartTime;
        // The amount of time (measured in seconds) that can elapse before the
        // lender can liquidate the loan and seize the underlying collateral.
        uint32 loanDuration;
        // If interestIsProRated is set to true, then this is the interest rate
        // (measured in basis points, e.g. hundreths of a percent) for the loan,
        // that must be repaid pro-rata by the borrower at the conclusion of
        // the loan or risk seizure of their nft collateral. Note that if
        // interestIsProRated is set to false, then this value is not used and
        // is irrelevant.
        uint32 loanInterestRateForDurationInBasisPoints;
        // The percent (measured in basis points) of the interest earned that
        // will be taken as a fee by the contract admins when the loan is
        // repaid. The fee is stored here to prevent an attack where the
        // contract admins could adjust the fee right before a loan is repaid,
        // and take all of the interest earned.
        uint32 loanAdminFeeInBasisPoints;
        // The ERC721 contract of the NFT collateral
        address nftCollateralContract;
        // The ERC20 contract of the currency being used as principal/interest
        // for this loan.
        address loanERC20Denomination;
        // The address of the borrower.
        address borrower;
        // A boolean value determining whether the interest will be pro-rated
        // if the loan is repaid early, or whether the borrower will simply
        // pay maximumRepaymentAmount.
        bool interestIsProRated;
    }

    // @notice This function gets the current chain ID.
    function getChainID() public view returns (uint256) {
        uint256 id;
        assembly {
            id := chainid()
        }
        return id;
    }

    // @notice This function is called in nftmortgage.beginLoan() to validate the
    //         borrower's signature that the borrower provided off-chain to
    //         verify that they did indeed want to agree to this loan according
    //         to these terms.
    // @param  _collateralRateInBasisPoints - Collateral rate in basis points 
    //         supplied from borrower to the partybid.
    // @param  _maximumRepaymentAmount - The maximum amount of money that the
    //         borrower would be required to retrieve their collateral. If
    //         interestIsProRated is set to false, then the borrower will
    //         always have to pay this amount to retrieve their collateral.
    // @param  _nftCollateralId - The ID within the NFTCollateralContract for
    //         the NFT being used as collateral for this loan. The NFT is
    //         stored within this contract during the duration of the loan.
    // @param  _loanDuration - The amount of time (measured in seconds) that can
    //         elapse before the lender can liquidate the loan and seize the
    //         underlying collateral NFT.
    // @param  _loanInterestRateForDurationInBasisPoints - The interest rate
    //         (measured in basis points, e.g. hundreths of a percent) for the
    //         loan, that must be repaid pro-rata by the borrower at the
    //         conclusion of the loan or risk seizure of their nft collateral.
    // @param  _adminFeeInBasisPoints - The percent (measured in basis
    //         points) of the interest earned that will be taken as a fee by
    //         the contract admins when the loan is repaid. The fee is stored
    //         in the loan struct to prevent an attack where the contract
    //         admins could adjust the fee right before a loan is repaid, and
    //         take all of the interest earned.
    // @param  _borrowerNonce - The nonce referred to here
    //         is not the same as an Ethereum account's nonce. We are referring
    //         instead to nonces that are used by both the lender and the
    //         borrower when they are first signing off-chain NFTfi orders.
    //         These nonces can be any uint256 value that the user has not
    //         previously used to sign an off-chain order. Each nonce can be
    //         used at most once per user within NFTfi, regardless of whether
    //         they are the lender or the borrower in that situation. This
    //         serves two purposes. First, it prevents replay attacks where an
    //         attacker would submit a user's off-chain order more than once.
    //         Second, it allows a user to cancel an off-chain order by calling
    //         NFTfi.cancelLoanCommitmentBeforeLoanHasBegun(), which marks the
    //         nonce as used and prevents any future loan from using the user's
    //         off-chain order that contains that nonce.
    // @param  _nftCollateralContract - The ERC721 contract of the NFT
    //         collateral
    // @param  _loanERC20Denomination - The ERC20 contract of the currency being
    //         used as principal/interest for this loan.
    // @param  _borrower - The address of the borrower. 
    // @param  _interestIsProRated - A boolean value determining whether the
    //         interest will be pro-rated if the loan is repaid early, or
    //         whether the borrower will simply pay maximumRepaymentAmount.
    // @param  _borrowerSignature - The ECDSA signature of the borrower,
    //         obtained off-chain ahead of time, signing the following
    //         combination of parameters: _loanPrincipalAmount,
    //         _maximumRepaymentAmount _nftCollateralId, _loanDuration,
    //         _loanInterestRateForDurationInBasisPoints, _borrowerNonce,
    //         _nftCollateralContract, _loanERC20Denomination, _borrower,
    //         _interestIsProRated.
    // @return A bool representing whether verification succeeded, showing that
    //         this signature matched this address and parameters.
    function isValidBorrowerSignature(
        uint256 _collateralRateInBasisPoints,
        // the above param will change with our implementation
        uint256 _maximumRepaymentAmount,
        uint256 _nftCollateralId,
        uint256 _loanDuration,
        uint256 _loanInterestRateForDurationInBasisPoints,
        uint256 _borrowerNonce,
        uint256 _maximumBid,
        address _nftCollateralContract,
        address _loanERC20Denomination,
        address _borrower,
        bool _interestIsProRated,
        bytes memory _borrowerSignature
    ) public view returns(bool) {
        if(_borrower == address(0)){
            return false;
        } else {
            uint256 chainId;
            chainId = getChainID();
            bytes32 message = keccak256(abi.encodePacked(
                _collateralRateInBasisPoints,
                _maximumRepaymentAmount,
                _nftCollateralId,
                _loanDuration,
                _loanInterestRateForDurationInBasisPoints,
                _borrowerNonce,
                _maximumBid,
                _nftCollateralContract,
                _loanERC20Denomination,
                _borrower,
                _interestIsProRated,
                chainId
            ));

            bytes32 messageWithEthSignPrefix = message.toEthSignedMessageHash();

            return (messageWithEthSignPrefix.recover(_borrowerSignature) == _borrower);
        }
    }

    // @notice A mapping that takes both a user's address and a loan nonce
    //         that was first used when signing an off-chain order and checks
    //         whether that nonce has previously either been used for a loan,
    //         or has been pre-emptively cancelled. The nonce referred to here
    //         is not the same as an Ethereum account's nonce. We are referring
    //         instead to nonces that are used by both the lender and the
    //         borrower when they are first signing off-chain NFTfi orders.
    //         These nonces can be any uint256 value that the user has not
    //         previously used to sign an off-chain order. Each nonce can be
    //         used at most once per user within NFTfi, regardless of whether
    //         they are the lender or the borrower in that situation. This
    //         serves two purposes. First, it prevents replay attacks where an
    //         attacker would submit a user's off-chain order more than once.
    //         Second, it allows a user to cancel an off-chain order by calling
    //         NFTfi.cancelLoanCommitmentBeforeLoanHasBegun(), which marks the
    //         nonce as used and prevents any future loan from using the user's
    //         off-chain order that contains that nonce.
    mapping (address => mapping (uint256 => bool)) private _nonceHasBeenUsedForUser;

    // @notice This function can be called by either a lender or a borrower to
    //         cancel all off-chain orders that they have signed that contain
    //         this nonce. If the off-chain orders were created correctly,
    //         there should only be one off-chain order that contains this
    //         nonce at all.

    function cancelLoanCommitmentBeforeLoanHasBegun(uint256 _nonce) external {
        require(!_nonceHasBeenUsedForUser[msg.sender][_nonce], 'Nonce invalid, user has either cancelled/begun this loan, or reused a nonce when signing');
        _nonceHasBeenUsedForUser[msg.sender][_nonce] = true;
    }
    // @notice This function can be used to view whether a particular nonce
    //         for a particular user has already been used, either from a
    //         successful loan or a cancelled off-chain order.
    // @param  _user - The address of the user. This function works for both
    //         lenders and borrowers alike.
    // @return A bool representing whether or not this nonce has been used for
    //         this user.
    function getWhetherNonceHasBeenUsedForUser(address _user, uint256 _nonce) public view returns (bool) {
        return _nonceHasBeenUsedForUser[_user][_nonce];
    }

       /* ******************* */
    /* READ-ONLY FUNCTIONS */
    /* ******************* */

    // @notice This function can be used to view the current quantity of the
    //         ERC20 currency used in the specified loan required by the
    //         borrower to repay their loan, measured in the smallest unit of
    //         the ERC20 currency. Note that since interest accrues every
    //         second, once a borrower calls repayLoan(), the amount will have
    //         increased slightly.
    // @param  _loanId  A unique identifier for this particular loan, sourced
    //         from the continuously increasing parameter totalNumLoans.
    // @return The amount of the specified ERC20 currency required to pay back
    //         this loan, measured in the smallest unit of the specified ERC20
    //         currency.
    function getPayoffAmount(uint256 _loanId) public view returns (uint256) {
        Loan storage loan = loanIdToLoan[_loanId];
        if(loan.interestIsProRated == false){
            return loan.maximumRepaymentAmount;
        } else {
            uint256 loanDurationSoFarInSeconds = block.timestamp.sub(uint256(loan.loanStartTime));
            uint256 interestDue = _computeInterestDue(loan.loanPrincipalAmount, loan.maximumRepaymentAmount, loanDurationSoFarInSeconds, uint256(loan.loanDuration), uint256(loan.loanInterestRateForDurationInBasisPoints));
            return (loan.loanPrincipalAmount).add(interestDue);
        }
    }

    /* ****************** */
    /* INTERNAL FUNCTIONS */
    /* ****************** */

    // @notice A convenience function that calculates the amount of interest
    //         currently due for a given loan. The interest is capped at
    //         _maximumRepaymentAmount minus _loanPrincipalAmount.
    // @param  _loanPrincipalAmount - The total quantity of principal first
    //         loaned to the borrower, measured in the smallest units of the
    //         ERC20 currency used for the loan.
    // @param  _maximumRepaymentAmount - The maximum amount of money that the
    //         borrower would be required to retrieve their collateral. If
    //         interestIsProRated is set to false, then the borrower will
    //         always have to pay this amount to retrieve their collateral.
    // @param  _loanDurationSoFarInSeconds - The elapsed time (in seconds) that
    //         has occurred so far since the loan began until repayment.
    // @param  _loanTotalDurationAgreedTo - The original duration that the
    //         borrower and lender agreed to, by which they measured the
    //         interest that would be due.
    // @param  _loanInterestRateForDurationInBasisPoints - The interest rate
    ///        that the borrower and lender agreed would be due after the
    //         totalDuration passed.
    // @return The quantity of interest due, measured in the smallest units of
    //         the ERC20 currency used to pay this loan.
    function _computeInterestDue(uint256 _loanPrincipalAmount, uint256 _maximumRepaymentAmount, uint256 _loanDurationSoFarInSeconds, uint256 _loanTotalDurationAgreedTo, uint256 _loanInterestRateForDurationInBasisPoints) internal pure returns (uint256) {
        uint256 interestDueAfterEntireDuration = (_loanPrincipalAmount.mul(_loanInterestRateForDurationInBasisPoints)).div(uint256(10000));
        uint256 interestDueAfterElapsedDuration = (interestDueAfterEntireDuration.mul(_loanDurationSoFarInSeconds)).div(_loanTotalDurationAgreedTo);
        if(_loanPrincipalAmount.add(interestDueAfterElapsedDuration) > _maximumRepaymentAmount){
            return _maximumRepaymentAmount.sub(_loanPrincipalAmount);
        } else {
            return interestDueAfterElapsedDuration;
        }
    }

    // @notice A convenience function computing the adminFee taken from a
    //         specified quantity of interest
    // @param  _interestDue - The amount of interest due, measured in the
    //         smallest quantity of the ERC20 currency being used to pay the
    //         interest.
    // @param  _adminFeeInBasisPoints - The percent (measured in basis
    //         points) of the interest earned that will be taken as a fee by
    //         the contract admins when the loan is repaid. The fee is stored
    //         in the loan struct to prevent an attack where the contract
    //         admins could adjust the fee right before a loan is repaid, and
    //         take all of the interest earned.
    // @return The quantity of ERC20 currency (measured in smalled units of
    //         that ERC20 currency) that is due as an admin fee.
    function _computeAdminFee(uint256 _interestDue, uint256 _adminFeeInBasisPoints) internal pure returns (uint256) {
    	return (_interestDue.mul(_adminFeeInBasisPoints)).div(10000);
    }

    // @notice This function attempts to call transferFrom() on the specified
    //         NFT contract, returning whether it succeeded.
    // @notice We only call this function from within _transferNftToAddress(),
    //         which is function attempts to call the various ways that
    //         different NFT contracts have implemented transfer/transferFrom.
    // @param  _nftContract - The NFT contract that we are attempting to
    //         transfer an NFT from.
    // @param  _nftId - The ID of the NFT that we are attempting to transfer.
    // @param  _recipient - The destination of the NFT that we are attempting
    //         to transfer.
    // @return A bool value indicating whether the transfer attempt succeeded.
    function _attemptTransferFrom(address _nftContract, uint256 _nftId, address _recipient) internal returns (bool) {
        // @notice Some NFT contracts will not allow you to approve an NFT that
        //         you own, so we cannot simply call approve() here, we have to
        //         try to call it in a manner that allows the call to fail.
        _nftContract.call(abi.encodeWithSelector(IERC721(_nftContract).approve.selector, address(this), _nftId));

        // @notice Some NFT contracts will not allow you to call transferFrom()
        //         for an NFT that you own but that is not approved, so we
        //         cannot simply call transferFrom() here, we have to try to
        //         call it in a manner that allows the call to fail.
        (bool success, ) = _nftContract.call(abi.encodeWithSelector(IERC721(_nftContract).transferFrom.selector, address(this), _recipient, _nftId));
        return success;
    }

}
