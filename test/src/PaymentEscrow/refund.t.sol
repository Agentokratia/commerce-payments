// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.28;

import {AuthCaptureEscrow} from "../../../src/AuthCaptureEscrow.sol";
import {AuthCaptureEscrowBase} from "../../base/AuthCaptureEscrowBase.sol";

contract RefundTest is AuthCaptureEscrowBase {
    uint120 constant CHARGE_AMOUNT = 100e6;
    uint256 constant REFUND_NONCE = 1;
    uint256 constant REFUND_DEADLINE = type(uint256).max;

    /// @dev Helper: charge a payment (using ERC3009) so there is a refundable amount
    function _chargePayment(AuthCaptureEscrow.PaymentInfo memory paymentInfo, uint120 amount) internal {
        bytes memory signature = _signERC3009ReceiveWithAuthorizationStruct(paymentInfo, payer_EOA_PK);
        vm.prank(operator);
        authCaptureEscrow.charge(
            paymentInfo,
            amount,
            address(erc3009PaymentCollector),
            signature,
            paymentInfo.minFeeBps,
            paymentInfo.feeReceiver
        );
    }

    /// @dev Helper: prepare receiver for refund (mint tokens, approve Permit2)
    function _prepareReceiverForRefund(address token, uint256 amount) internal {
        if (token == address(mockERC3009Token)) {
            mockERC3009Token.mint(receiver, amount);
            vm.prank(receiver);
            mockERC3009Token.approve(address(permit2), type(uint256).max);
        } else {
            mockERC20Token.mint(receiver, amount);
            vm.prank(receiver);
            mockERC20Token.approve(address(permit2), type(uint256).max);
        }
    }

    /// @dev Helper: encode MerchantRefundCollector data
    function _encodeRefundCollectorData(uint256 nonce, uint256 deadline, bytes memory signature)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encode(nonce, deadline, signature);
    }

    // =========================================================================
    // Revert tests
    // =========================================================================

    function test_reverts_whenValueIsZero() public {
        AuthCaptureEscrow.PaymentInfo memory paymentInfo =
            _createPaymentInfo({payer: payerEOA, maxAmount: CHARGE_AMOUNT});
        _chargePayment(paymentInfo, CHARGE_AMOUNT);

        vm.prank(operator);
        vm.expectRevert(AuthCaptureEscrow.ZeroAmount.selector);
        authCaptureEscrow.refund(paymentInfo, 0, address(merchantRefundCollector), "");
    }

    function test_reverts_whenSenderNotOperator() public {
        AuthCaptureEscrow.PaymentInfo memory paymentInfo =
            _createPaymentInfo({payer: payerEOA, maxAmount: CHARGE_AMOUNT});
        _chargePayment(paymentInfo, CHARGE_AMOUNT);

        address notOperator = vm.addr(999);
        vm.prank(notOperator);
        vm.expectRevert(abi.encodeWithSelector(AuthCaptureEscrow.InvalidSender.selector, notOperator, operator));
        authCaptureEscrow.refund(paymentInfo, 1, address(merchantRefundCollector), "");
    }

    function test_reverts_afterRefundExpiry() public {
        AuthCaptureEscrow.PaymentInfo memory paymentInfo =
            _createPaymentInfo({payer: payerEOA, maxAmount: CHARGE_AMOUNT});
        // Set a finite refund expiry
        paymentInfo.preApprovalExpiry = uint48(block.timestamp + 100);
        paymentInfo.authorizationExpiry = uint48(block.timestamp + 200);
        paymentInfo.refundExpiry = uint48(block.timestamp + 300);

        // Charge with updated paymentInfo
        bytes memory sig = _signERC3009ReceiveWithAuthorizationStruct(paymentInfo, payer_EOA_PK);
        vm.prank(operator);
        authCaptureEscrow.charge(
            paymentInfo,
            CHARGE_AMOUNT,
            address(erc3009PaymentCollector),
            sig,
            paymentInfo.minFeeBps,
            paymentInfo.feeReceiver
        );

        // Warp past refund expiry
        vm.warp(block.timestamp + 301);

        vm.prank(operator);
        vm.expectRevert(
            abi.encodeWithSelector(
                AuthCaptureEscrow.AfterRefundExpiry.selector, uint48(block.timestamp), paymentInfo.refundExpiry
            )
        );
        authCaptureEscrow.refund(paymentInfo, 1, address(merchantRefundCollector), "");
    }

    function test_reverts_whenRefundExceedsCapture() public {
        AuthCaptureEscrow.PaymentInfo memory paymentInfo =
            _createPaymentInfo({payer: payerEOA, maxAmount: CHARGE_AMOUNT});
        _chargePayment(paymentInfo, CHARGE_AMOUNT);

        // Compute the actual refundable (captured amount minus fees already distributed = full charge amount is refundable)
        // The refundableAmount is set to the charge amount in the contract
        uint256 refundAmount = uint256(CHARGE_AMOUNT) + 1;

        _prepareReceiverForRefund(address(mockERC3009Token), refundAmount);
        bytes memory refundSig = _signPermit2RefundTransfer(
            address(mockERC3009Token), refundAmount, REFUND_DEADLINE, REFUND_NONCE, RECEIVER_PK
        );
        bytes memory collectorData = _encodeRefundCollectorData(REFUND_NONCE, REFUND_DEADLINE, refundSig);

        vm.prank(operator);
        vm.expectRevert(
            abi.encodeWithSelector(AuthCaptureEscrow.RefundExceedsCapture.selector, refundAmount, CHARGE_AMOUNT)
        );
        authCaptureEscrow.refund(paymentInfo, refundAmount, address(merchantRefundCollector), collectorData);
    }

    function test_reverts_whenCollectorTypeIsPayment() public {
        AuthCaptureEscrow.PaymentInfo memory paymentInfo =
            _createPaymentInfo({payer: payerEOA, maxAmount: CHARGE_AMOUNT});
        _chargePayment(paymentInfo, CHARGE_AMOUNT);

        // Use a Payment-type collector for a refund — should revert
        _prepareReceiverForRefund(address(mockERC3009Token), CHARGE_AMOUNT);

        vm.prank(operator);
        vm.expectRevert(AuthCaptureEscrow.InvalidCollectorForOperation.selector);
        authCaptureEscrow.refund(paymentInfo, CHARGE_AMOUNT, address(permit2PaymentCollector), "");
    }

    // =========================================================================
    // Success tests
    // =========================================================================

    function test_succeeds_fullRefund() public {
        AuthCaptureEscrow.PaymentInfo memory paymentInfo =
            _createPaymentInfo({payer: payerEOA, maxAmount: CHARGE_AMOUNT});
        _chargePayment(paymentInfo, CHARGE_AMOUNT);

        uint256 payerBalanceBefore = mockERC3009Token.balanceOf(payerEOA);

        _prepareReceiverForRefund(address(mockERC3009Token), CHARGE_AMOUNT);
        bytes memory refundSig = _signPermit2RefundTransfer(
            address(mockERC3009Token), CHARGE_AMOUNT, REFUND_DEADLINE, REFUND_NONCE, RECEIVER_PK
        );
        bytes memory collectorData = _encodeRefundCollectorData(REFUND_NONCE, REFUND_DEADLINE, refundSig);

        vm.prank(operator);
        authCaptureEscrow.refund(paymentInfo, CHARGE_AMOUNT, address(merchantRefundCollector), collectorData);

        // Payer gets full refund
        assertEq(mockERC3009Token.balanceOf(payerEOA), payerBalanceBefore + CHARGE_AMOUNT);

        // Refundable amount is now 0
        bytes32 paymentInfoHash = authCaptureEscrow.getHash(paymentInfo);
        (,, uint120 refundableAmount) = authCaptureEscrow.paymentState(paymentInfoHash);
        assertEq(refundableAmount, 0);
    }

    function test_succeeds_partialRefund() public {
        AuthCaptureEscrow.PaymentInfo memory paymentInfo =
            _createPaymentInfo({payer: payerEOA, maxAmount: CHARGE_AMOUNT});
        _chargePayment(paymentInfo, CHARGE_AMOUNT);

        uint120 refundAmount = CHARGE_AMOUNT / 2;
        uint256 payerBalanceBefore = mockERC3009Token.balanceOf(payerEOA);

        _prepareReceiverForRefund(address(mockERC3009Token), refundAmount);
        bytes memory refundSig = _signPermit2RefundTransfer(
            address(mockERC3009Token), refundAmount, REFUND_DEADLINE, REFUND_NONCE, RECEIVER_PK
        );
        bytes memory collectorData = _encodeRefundCollectorData(REFUND_NONCE, REFUND_DEADLINE, refundSig);

        vm.prank(operator);
        authCaptureEscrow.refund(paymentInfo, refundAmount, address(merchantRefundCollector), collectorData);

        assertEq(mockERC3009Token.balanceOf(payerEOA), payerBalanceBefore + refundAmount);

        bytes32 paymentInfoHash = authCaptureEscrow.getHash(paymentInfo);
        (,, uint120 refundableAmount) = authCaptureEscrow.paymentState(paymentInfoHash);
        assertEq(refundableAmount, CHARGE_AMOUNT - refundAmount);
    }

    function test_succeeds_multiplePartialRefunds() public {
        AuthCaptureEscrow.PaymentInfo memory paymentInfo =
            _createPaymentInfo({payer: payerEOA, maxAmount: CHARGE_AMOUNT});
        _chargePayment(paymentInfo, CHARGE_AMOUNT);

        uint120 firstRefund = CHARGE_AMOUNT / 4;
        uint120 secondRefund = CHARGE_AMOUNT / 4;
        uint256 payerBalanceBefore = mockERC3009Token.balanceOf(payerEOA);

        // First partial refund (nonce = 1)
        _prepareReceiverForRefund(address(mockERC3009Token), firstRefund);
        bytes memory refundSig1 =
            _signPermit2RefundTransfer(address(mockERC3009Token), firstRefund, REFUND_DEADLINE, 1, RECEIVER_PK);
        bytes memory collectorData1 = _encodeRefundCollectorData(1, REFUND_DEADLINE, refundSig1);

        vm.prank(operator);
        authCaptureEscrow.refund(paymentInfo, firstRefund, address(merchantRefundCollector), collectorData1);

        // Second partial refund (nonce = 2)
        _prepareReceiverForRefund(address(mockERC3009Token), secondRefund);
        bytes memory refundSig2 =
            _signPermit2RefundTransfer(address(mockERC3009Token), secondRefund, REFUND_DEADLINE, 2, RECEIVER_PK);
        bytes memory collectorData2 = _encodeRefundCollectorData(2, REFUND_DEADLINE, refundSig2);

        vm.prank(operator);
        authCaptureEscrow.refund(paymentInfo, secondRefund, address(merchantRefundCollector), collectorData2);

        assertEq(mockERC3009Token.balanceOf(payerEOA), payerBalanceBefore + firstRefund + secondRefund);

        bytes32 paymentInfoHash = authCaptureEscrow.getHash(paymentInfo);
        (,, uint120 refundableAmount) = authCaptureEscrow.paymentState(paymentInfoHash);
        assertEq(refundableAmount, CHARGE_AMOUNT - firstRefund - secondRefund);
    }

    function test_emitsPaymentRefundedEvent() public {
        AuthCaptureEscrow.PaymentInfo memory paymentInfo =
            _createPaymentInfo({payer: payerEOA, maxAmount: CHARGE_AMOUNT});
        _chargePayment(paymentInfo, CHARGE_AMOUNT);

        _prepareReceiverForRefund(address(mockERC3009Token), CHARGE_AMOUNT);
        bytes memory refundSig = _signPermit2RefundTransfer(
            address(mockERC3009Token), CHARGE_AMOUNT, REFUND_DEADLINE, REFUND_NONCE, RECEIVER_PK
        );
        bytes memory collectorData = _encodeRefundCollectorData(REFUND_NONCE, REFUND_DEADLINE, refundSig);

        bytes32 paymentInfoHash = authCaptureEscrow.getHash(paymentInfo);

        vm.expectEmit(true, false, false, true);
        emit AuthCaptureEscrow.PaymentRefunded(paymentInfoHash, CHARGE_AMOUNT, address(merchantRefundCollector));

        vm.prank(operator);
        authCaptureEscrow.refund(paymentInfo, CHARGE_AMOUNT, address(merchantRefundCollector), collectorData);
    }
}
