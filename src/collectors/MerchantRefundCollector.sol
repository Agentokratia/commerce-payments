// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 *         ●     ●     ●
 *              ╱╲
 *             ╱  ╲
 *            ╱    ╲
 *           ╱  ╱╲  ╲
 *          ╱__╱  ╲__╲
 *
 *       AGENTOKRATIA
 *
 *  Your agents. Your keys. Your economy.
 *
 *  Built on top of Commerce Payments Protocol by Coinbase
 *  https://github.com/base/commerce-payments
 */
import {ISignatureTransfer} from "permit2/interfaces/ISignatureTransfer.sol";

import {TokenCollector} from "./TokenCollector.sol";
import {ERC6492SignatureHandler} from "./ERC6492SignatureHandler.sol";
import {AuthCaptureEscrow} from "../AuthCaptureEscrow.sol";

/// @title MerchantRefundCollector
///
/// @notice Collect refund tokens from merchants using Permit2 signatures
///
/// @dev Mirrors Permit2PaymentCollector with three key differences:
///      1. collectorType = Refund (not Payment)
///      2. owner = paymentInfo.receiver (merchant, not payer)
///      3. collectorData = abi.encode(uint256 nonce, uint256 deadline, bytes signature)
///         Merchant-chosen nonce allows multiple partial refunds per payment.
///
/// @author Agentokratia
contract MerchantRefundCollector is TokenCollector, ERC6492SignatureHandler {
    /// @inheritdoc TokenCollector
    TokenCollector.CollectorType public constant override collectorType = TokenCollector.CollectorType.Refund;

    /// @notice Permit2 singleton
    ISignatureTransfer public immutable permit2;

    /// @notice Constructor
    ///
    /// @param authCaptureEscrow_ AuthCaptureEscrow singleton that calls to collect tokens
    /// @param permit2_ Permit2 singleton
    /// @param multicall3_ Public Multicall3 singleton for safe ERC-6492 external calls
    constructor(address authCaptureEscrow_, address permit2_, address multicall3_)
        TokenCollector(authCaptureEscrow_)
        ERC6492SignatureHandler(multicall3_)
    {
        permit2 = ISignatureTransfer(permit2_);
    }

    /// @inheritdoc TokenCollector
    ///
    /// @dev Use Permit2 signature transfer to collect refund tokens from merchant (receiver)
    ///
    /// @dev collectorData is abi.encode(uint256 nonce, uint256 deadline, bytes signature)
    ///      The merchant picks a unique nonce per refund to support multiple partial refunds.
    function _collectTokens(
        AuthCaptureEscrow.PaymentInfo calldata paymentInfo,
        address tokenStore,
        uint256 amount,
        bytes calldata collectorData
    ) internal override {
        (uint256 nonce, uint256 deadline, bytes memory signature) = abi.decode(collectorData, (uint256, uint256, bytes));

        permit2.permitTransferFrom({
            permit: ISignatureTransfer.PermitTransferFrom({
                permitted: ISignatureTransfer.TokenPermissions({token: paymentInfo.token, amount: amount}),
                nonce: nonce,
                deadline: deadline
            }),
            transferDetails: ISignatureTransfer.SignatureTransferDetails({to: tokenStore, requestedAmount: amount}),
            owner: paymentInfo.receiver,
            signature: _handleERC6492Signature(signature)
        });
    }
}
