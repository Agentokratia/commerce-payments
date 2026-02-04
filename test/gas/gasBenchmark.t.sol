// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.28;

import {AuthCaptureEscrow} from "../../src/AuthCaptureEscrow.sol";

import {AuthCaptureEscrowBase} from "../base/AuthCaptureEscrowBase.sol";

contract GasBenchmarkBase is AuthCaptureEscrowBase {
    uint120 internal constant BENCHMARK_AMOUNT = 100e6;
    uint16 internal constant BENCHMARK_FEE_BPS = 100; // 1%

    AuthCaptureEscrow.PaymentInfo internal paymentInfo;
    bytes internal signature;

    function setUp() public virtual override {
        super.setUp();

        // Perform warmup authorization to handle first-time deployment costs associated with future potential design iterations
        AuthCaptureEscrow.PaymentInfo memory warmupInfo = _createPaymentInfo(payerEOA, 1e6);
        warmupInfo.salt = 1; // different salt to avoid paymentInfo hash collision
        bytes memory warmupSignature = _signERC3009ReceiveWithAuthorizationStruct(warmupInfo, payer_EOA_PK);
        mockERC3009Token.mint(payerEOA, 1e6);
        vm.startPrank(operator);
        authCaptureEscrow.authorize(warmupInfo, 1e6, address(erc3009PaymentCollector), warmupSignature);
        authCaptureEscrow.capture(warmupInfo, 1e6, BENCHMARK_FEE_BPS, feeReceiver); // make sure token store is deployed before subsequent tests
        vm.stopPrank();

        // Create and sign payment info
        paymentInfo = _createPaymentInfo(payerEOA, BENCHMARK_AMOUNT);
        signature = _signERC3009ReceiveWithAuthorizationStruct(paymentInfo, payer_EOA_PK);

        // Give payer tokens
        mockERC3009Token.mint(payerEOA, BENCHMARK_AMOUNT);
    }
}

contract AuthorizeGasBenchmark is GasBenchmarkBase {
    function test_authorize_benchmark() public {
        vm.prank(operator);
        authCaptureEscrow.authorize(paymentInfo, BENCHMARK_AMOUNT, address(erc3009PaymentCollector), signature);
    }
}

contract ChargeGasBenchmark is GasBenchmarkBase {
    function test_charge_benchmark() public {
        vm.prank(operator);
        authCaptureEscrow.charge(
            paymentInfo, BENCHMARK_AMOUNT, address(erc3009PaymentCollector), signature, BENCHMARK_FEE_BPS, feeReceiver
        );
    }
}

contract CaptureGasBenchmark is GasBenchmarkBase {
    function setUp() public override {
        super.setUp();

        // Pre-authorize
        vm.prank(operator);
        authCaptureEscrow.authorize(paymentInfo, BENCHMARK_AMOUNT, address(erc3009PaymentCollector), signature);
    }

    function test_capture_benchmark() public {
        vm.prank(operator);
        authCaptureEscrow.capture(paymentInfo, BENCHMARK_AMOUNT, BENCHMARK_FEE_BPS, feeReceiver);
    }
}

contract VoidGasBenchmark is GasBenchmarkBase {
    function setUp() public override {
        super.setUp();

        // Pre-authorize
        vm.prank(operator);
        authCaptureEscrow.authorize(paymentInfo, BENCHMARK_AMOUNT, address(erc3009PaymentCollector), signature);
    }

    function test_void_benchmark() public {
        vm.prank(operator);
        authCaptureEscrow.void(paymentInfo);
    }
}

contract ReclaimGasBenchmark is GasBenchmarkBase {
    function setUp() public override {
        super.setUp();

        // Pre-authorize
        vm.prank(operator);
        authCaptureEscrow.authorize(paymentInfo, BENCHMARK_AMOUNT, address(erc3009PaymentCollector), signature);

        // Warp past authorization expiry
        vm.warp(paymentInfo.authorizationExpiry);
    }

    function test_reclaim_benchmark() public {
        vm.prank(payerEOA);
        authCaptureEscrow.reclaim(paymentInfo);
    }
}

contract RefundGasBenchmark is GasBenchmarkBase {
    function setUp() public override {
        super.setUp();

        // Pre-authorize and capture
        vm.prank(operator);
        authCaptureEscrow.authorize(paymentInfo, BENCHMARK_AMOUNT, address(erc3009PaymentCollector), signature);
        vm.prank(operator);
        authCaptureEscrow.capture(paymentInfo, BENCHMARK_AMOUNT, BENCHMARK_FEE_BPS, feeReceiver);

        // Give receiver tokens for refund and approve Permit2
        mockERC3009Token.mint(receiver, BENCHMARK_AMOUNT);
        vm.prank(receiver);
        mockERC3009Token.approve(address(permit2), type(uint256).max);
    }

    function test_refund_benchmark() public {
        bytes memory refundSig = _signPermit2RefundTransfer(
            address(mockERC3009Token), BENCHMARK_AMOUNT, type(uint256).max, 1, RECEIVER_PK
        );
        bytes memory collectorData = abi.encode(uint256(1), type(uint256).max, refundSig);

        vm.prank(operator);
        authCaptureEscrow.refund(paymentInfo, BENCHMARK_AMOUNT, address(merchantRefundCollector), collectorData);
    }
}
