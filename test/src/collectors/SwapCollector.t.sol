// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.28;

import {AuthCaptureEscrow} from "../../../src/AuthCaptureEscrow.sol";
import {TokenCollector} from "../../../src/collectors/TokenCollector.sol";
import {
    SwapCollector, SWAP_WITNESS_TYPE_STRING, SWAP_WITNESS_TYPEHASH
} from "../../../src/collectors/SwapCollector.sol";

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ISignatureTransfer} from "permit2/interfaces/ISignatureTransfer.sol";
import {IPermit2} from "permit2/interfaces/IPermit2.sol";
import {MockERC20} from "solady/../test/utils/mocks/MockERC20.sol";

import {CoinbaseSmartWallet} from "smart-wallet/CoinbaseSmartWallet.sol";

import {AuthCaptureEscrowSmartWalletBase} from "../../base/AuthCaptureEscrowSmartWalletBase.sol";
import {MockDEXAggregator} from "../../mocks/MockDEXAggregator.sol";

contract SwapCollectorTest is AuthCaptureEscrowSmartWalletBase {
    SwapCollector public swapCollector;
    address public swapCollectorOwner;
    MockERC20 public inputToken;
    MockDEXAggregator public aggregator;

    // Permit2 witness typehash constants
    bytes32 constant _TOKEN_PERMISSIONS_TYPEHASH_LOCAL = keccak256("TokenPermissions(address token,uint256 amount)");
    string constant _PERMIT_TRANSFER_FROM_WITNESS_TYPEHASH_STUB =
        "PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,";

    function setUp() public override {
        super.setUp();

        // Deploy input token (different from the output token used in paymentInfo)
        inputToken = new MockERC20("Mock WETH", "mWETH", 18);

        // Deploy mock aggregator
        aggregator = new MockDEXAggregator();

        // Deploy SwapCollector
        swapCollectorOwner = makeAddr("swapCollectorOwner");
        swapCollector = new SwapCollector(address(authCaptureEscrow), permit2, multicall3, swapCollectorOwner);

        // Whitelist tokens and aggregator
        vm.startPrank(swapCollectorOwner);
        swapCollector.whitelistToken(address(inputToken), true);
        swapCollector.whitelistAggregator(address(aggregator), true);
        vm.stopPrank();

        // Mint input tokens to payer and approve Permit2
        inputToken.mint(payerEOA, 1000e18);
        vm.prank(payerEOA);
        inputToken.approve(address(permit2), type(uint256).max);

        // Also set up smart wallets with input token approvals
        vm.prank(address(smartWalletDeployed));
        inputToken.approve(address(permit2), type(uint256).max);
        vm.prank(smartWalletCounterfactual);
        inputToken.approve(address(permit2), type(uint256).max);
    }

    // =========================================================================
    // Access Control
    // =========================================================================

    function test_collectTokens_reverts_whenCalledByNonAuthCaptureEscrow() public {
        uint120 amount = 100e6;
        AuthCaptureEscrow.PaymentInfo memory paymentInfo = _createPaymentInfo(payerEOA, amount, address(mockERC20Token));
        address tokenStore = authCaptureEscrow.getTokenStore(paymentInfo.operator);

        vm.expectRevert(abi.encodeWithSelector(TokenCollector.OnlyAuthCaptureEscrow.selector));
        swapCollector.collectTokens(paymentInfo, tokenStore, amount, "");
    }

    // =========================================================================
    // Collector Type
    // =========================================================================

    function test_collectorType_returnsPayment() public view {
        assertEq(uint256(swapCollector.collectorType()), uint256(TokenCollector.CollectorType.Payment));
    }

    // =========================================================================
    // Admin: Token Whitelist
    // =========================================================================

    function test_whitelistToken_succeeds_whenCalledByOwner() public {
        address newToken = address(0xBEEF);

        vm.prank(swapCollectorOwner);
        vm.expectEmit(true, false, false, true);
        emit SwapCollector.TokenWhitelistUpdated(newToken, true);
        swapCollector.whitelistToken(newToken, true);

        assertTrue(swapCollector.whitelistedTokens(newToken));
    }

    function test_whitelistToken_reverts_whenCalledByNonOwner() public {
        vm.prank(address(0xDEAD));
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(0xDEAD)));
        swapCollector.whitelistToken(address(0xBEEF), true);
    }

    function test_whitelistToken_removesToken() public {
        vm.startPrank(swapCollectorOwner);
        swapCollector.whitelistToken(address(0xBEEF), true);
        assertTrue(swapCollector.whitelistedTokens(address(0xBEEF)));

        swapCollector.whitelistToken(address(0xBEEF), false);
        assertFalse(swapCollector.whitelistedTokens(address(0xBEEF)));
        vm.stopPrank();
    }

    // =========================================================================
    // Admin: Aggregator Whitelist
    // =========================================================================

    function test_whitelistAggregator_succeeds_whenCalledByOwner() public {
        address newAgg = address(0xCAFE);

        vm.prank(swapCollectorOwner);
        vm.expectEmit(true, false, false, true);
        emit SwapCollector.AggregatorWhitelistUpdated(newAgg, true);
        swapCollector.whitelistAggregator(newAgg, true);

        assertTrue(swapCollector.whitelistedAggregators(newAgg));
    }

    function test_whitelistAggregator_reverts_whenCalledByNonOwner() public {
        vm.prank(address(0xDEAD));
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(0xDEAD)));
        swapCollector.whitelistAggregator(address(0xCAFE), true);
    }

    // =========================================================================
    // Admin: Batch Whitelist
    // =========================================================================

    function test_whitelistTokens_batch() public {
        address[] memory tokens = new address[](2);
        tokens[0] = address(0xAAA);
        tokens[1] = address(0xBBB);
        bool[] memory allowed = new bool[](2);
        allowed[0] = true;
        allowed[1] = true;

        vm.prank(swapCollectorOwner);
        swapCollector.whitelistTokens(tokens, allowed);

        assertTrue(swapCollector.whitelistedTokens(address(0xAAA)));
        assertTrue(swapCollector.whitelistedTokens(address(0xBBB)));
    }

    function test_whitelistTokens_reverts_arrayLengthMismatch() public {
        address[] memory tokens = new address[](2);
        tokens[0] = address(0xAAA);
        tokens[1] = address(0xBBB);
        bool[] memory allowed = new bool[](1);
        allowed[0] = true;

        vm.prank(swapCollectorOwner);
        vm.expectRevert(abi.encodeWithSelector(SwapCollector.ArrayLengthMismatch.selector));
        swapCollector.whitelistTokens(tokens, allowed);
    }

    function test_whitelistAggregators_batch() public {
        address[] memory aggs = new address[](2);
        aggs[0] = address(0xCCC);
        aggs[1] = address(0xDDD);
        bool[] memory allowed = new bool[](2);
        allowed[0] = true;
        allowed[1] = true;

        vm.prank(swapCollectorOwner);
        swapCollector.whitelistAggregators(aggs, allowed);

        assertTrue(swapCollector.whitelistedAggregators(address(0xCCC)));
        assertTrue(swapCollector.whitelistedAggregators(address(0xDDD)));
    }

    function test_whitelistAggregators_reverts_arrayLengthMismatch() public {
        address[] memory aggs = new address[](1);
        aggs[0] = address(0xCCC);
        bool[] memory allowed = new bool[](2);
        allowed[0] = true;
        allowed[1] = true;

        vm.prank(swapCollectorOwner);
        vm.expectRevert(abi.encodeWithSelector(SwapCollector.ArrayLengthMismatch.selector));
        swapCollector.whitelistAggregators(aggs, allowed);
    }

    // =========================================================================
    // Admin: Pause
    // =========================================================================

    function test_pause_succeeds_whenCalledByOwner() public {
        vm.prank(swapCollectorOwner);
        swapCollector.pause();
        assertTrue(swapCollector.paused());
    }

    function test_pause_reverts_whenCalledByNonOwner() public {
        vm.prank(address(0xDEAD));
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(0xDEAD)));
        swapCollector.pause();
    }

    function test_unpause_succeeds_whenCalledByOwner() public {
        vm.startPrank(swapCollectorOwner);
        swapCollector.pause();
        swapCollector.unpause();
        vm.stopPrank();
        assertFalse(swapCollector.paused());
    }

    function test_unpause_reverts_whenCalledByNonOwner() public {
        vm.prank(swapCollectorOwner);
        swapCollector.pause();

        vm.prank(address(0xDEAD));
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(0xDEAD)));
        swapCollector.unpause();
    }

    // =========================================================================
    // Admin: Emergency Withdraw
    // =========================================================================

    function test_emergencyWithdraw_succeeds() public {
        // Send some tokens to the collector
        inputToken.mint(address(swapCollector), 50e18);

        vm.prank(swapCollectorOwner);
        vm.expectEmit(true, true, false, true);
        emit SwapCollector.EmergencyWithdraw(address(inputToken), swapCollectorOwner, 50e18);
        swapCollector.emergencyWithdraw(address(inputToken), swapCollectorOwner, 50e18);

        assertEq(inputToken.balanceOf(swapCollectorOwner), 50e18);
    }

    function test_emergencyWithdraw_reverts_whenCalledByNonOwner() public {
        vm.prank(address(0xDEAD));
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(0xDEAD)));
        swapCollector.emergencyWithdraw(address(inputToken), address(0xDEAD), 1);
    }

    // =========================================================================
    // Admin: Ownership
    // =========================================================================

    function test_transferOwnership_twoStep() public {
        address newOwner = address(0xABCD);

        vm.prank(swapCollectorOwner);
        swapCollector.transferOwnership(newOwner);

        // Not yet transferred
        assertEq(swapCollector.owner(), swapCollectorOwner);

        // Accept ownership
        vm.prank(newOwner);
        swapCollector.acceptOwnership();
        assertEq(swapCollector.owner(), newOwner);
    }

    // =========================================================================
    // Whitelist Validation
    // =========================================================================

    function test_collectTokens_reverts_tokenNotWhitelisted() public {
        uint120 outputAmount = 100e6;
        AuthCaptureEscrow.PaymentInfo memory paymentInfo =
            _createPaymentInfo(payerEOA, outputAmount, address(mockERC20Token));
        address tokenStore = authCaptureEscrow.getTokenStore(paymentInfo.operator);

        // Use a non-whitelisted input token
        address badToken = address(new MockERC20("Bad", "BAD", 18));

        SwapCollector.SwapData memory swapData = SwapCollector.SwapData({
            inputToken: badToken,
            maxInputAmount: 1e18,
            aggregator: address(aggregator),
            aggregatorCalldata: abi.encodeCall(
                MockDEXAggregator.swap, (badToken, address(mockERC20Token), 1e18, outputAmount)
            )
        });

        bytes memory sig = _signPermit2WitnessTransfer(paymentInfo, swapData, payer_EOA_PK);
        bytes memory collectorData = abi.encode(swapData, sig);

        vm.prank(address(authCaptureEscrow));
        vm.expectRevert(abi.encodeWithSelector(SwapCollector.TokenNotWhitelisted.selector, badToken));
        swapCollector.collectTokens(paymentInfo, tokenStore, outputAmount, collectorData);
    }

    function test_collectTokens_reverts_aggregatorNotWhitelisted() public {
        uint120 outputAmount = 100e6;
        AuthCaptureEscrow.PaymentInfo memory paymentInfo =
            _createPaymentInfo(payerEOA, outputAmount, address(mockERC20Token));
        address tokenStore = authCaptureEscrow.getTokenStore(paymentInfo.operator);

        address badAggregator = address(0xBADA66);

        SwapCollector.SwapData memory swapData = SwapCollector.SwapData({
            inputToken: address(inputToken),
            maxInputAmount: 1e18,
            aggregator: badAggregator,
            aggregatorCalldata: abi.encodeCall(
                MockDEXAggregator.swap, (address(inputToken), address(mockERC20Token), 1e18, outputAmount)
            )
        });

        bytes memory sig = _signPermit2WitnessTransfer(paymentInfo, swapData, payer_EOA_PK);
        bytes memory collectorData = abi.encode(swapData, sig);

        vm.prank(address(authCaptureEscrow));
        vm.expectRevert(abi.encodeWithSelector(SwapCollector.AggregatorNotWhitelisted.selector, badAggregator));
        swapCollector.collectTokens(paymentInfo, tokenStore, outputAmount, collectorData);
    }

    // =========================================================================
    // Input Validation
    // =========================================================================

    function test_collectTokens_reverts_sameInputOutputToken() public {
        uint120 outputAmount = 100e6;
        AuthCaptureEscrow.PaymentInfo memory paymentInfo =
            _createPaymentInfo(payerEOA, outputAmount, address(mockERC20Token));
        address tokenStore = authCaptureEscrow.getTokenStore(paymentInfo.operator);

        // Input token == output token (paymentInfo.token)
        SwapCollector.SwapData memory swapData = SwapCollector.SwapData({
            inputToken: address(mockERC20Token),
            maxInputAmount: 1e18,
            aggregator: address(aggregator),
            aggregatorCalldata: hex"deadbeef"
        });

        bytes memory collectorData = abi.encode(swapData, hex"");

        vm.prank(address(authCaptureEscrow));
        vm.expectRevert(abi.encodeWithSelector(SwapCollector.SameInputOutputToken.selector));
        swapCollector.collectTokens(paymentInfo, tokenStore, outputAmount, collectorData);
    }

    function test_collectTokens_reverts_zeroInputToken() public {
        uint120 outputAmount = 100e6;
        AuthCaptureEscrow.PaymentInfo memory paymentInfo =
            _createPaymentInfo(payerEOA, outputAmount, address(mockERC20Token));
        address tokenStore = authCaptureEscrow.getTokenStore(paymentInfo.operator);

        SwapCollector.SwapData memory swapData = SwapCollector.SwapData({
            inputToken: address(0),
            maxInputAmount: 1e18,
            aggregator: address(aggregator),
            aggregatorCalldata: hex"deadbeef"
        });

        bytes memory collectorData = abi.encode(swapData, hex"");

        vm.prank(address(authCaptureEscrow));
        vm.expectRevert(abi.encodeWithSelector(SwapCollector.ZeroInputToken.selector));
        swapCollector.collectTokens(paymentInfo, tokenStore, outputAmount, collectorData);
    }

    function test_collectTokens_reverts_zeroAggregator() public {
        uint120 outputAmount = 100e6;
        AuthCaptureEscrow.PaymentInfo memory paymentInfo =
            _createPaymentInfo(payerEOA, outputAmount, address(mockERC20Token));
        address tokenStore = authCaptureEscrow.getTokenStore(paymentInfo.operator);

        SwapCollector.SwapData memory swapData = SwapCollector.SwapData({
            inputToken: address(inputToken),
            maxInputAmount: 1e18,
            aggregator: address(0),
            aggregatorCalldata: hex"deadbeef"
        });

        bytes memory collectorData = abi.encode(swapData, hex"");

        vm.prank(address(authCaptureEscrow));
        vm.expectRevert(abi.encodeWithSelector(SwapCollector.ZeroAggregator.selector));
        swapCollector.collectTokens(paymentInfo, tokenStore, outputAmount, collectorData);
    }

    function test_collectTokens_reverts_zeroMaxInputAmount() public {
        uint120 outputAmount = 100e6;
        AuthCaptureEscrow.PaymentInfo memory paymentInfo =
            _createPaymentInfo(payerEOA, outputAmount, address(mockERC20Token));
        address tokenStore = authCaptureEscrow.getTokenStore(paymentInfo.operator);

        SwapCollector.SwapData memory swapData = SwapCollector.SwapData({
            inputToken: address(inputToken),
            maxInputAmount: 0,
            aggregator: address(aggregator),
            aggregatorCalldata: hex"deadbeef"
        });

        bytes memory collectorData = abi.encode(swapData, hex"");

        vm.prank(address(authCaptureEscrow));
        vm.expectRevert(abi.encodeWithSelector(SwapCollector.ZeroMaxInputAmount.selector));
        swapCollector.collectTokens(paymentInfo, tokenStore, outputAmount, collectorData);
    }

    function test_collectTokens_reverts_emptyAggregatorCalldata() public {
        uint120 outputAmount = 100e6;
        AuthCaptureEscrow.PaymentInfo memory paymentInfo =
            _createPaymentInfo(payerEOA, outputAmount, address(mockERC20Token));
        address tokenStore = authCaptureEscrow.getTokenStore(paymentInfo.operator);

        SwapCollector.SwapData memory swapData = SwapCollector.SwapData({
            inputToken: address(inputToken),
            maxInputAmount: 1e18,
            aggregator: address(aggregator),
            aggregatorCalldata: hex""
        });

        bytes memory collectorData = abi.encode(swapData, hex"");

        vm.prank(address(authCaptureEscrow));
        vm.expectRevert(abi.encodeWithSelector(SwapCollector.EmptyAggregatorCalldata.selector));
        swapCollector.collectTokens(paymentInfo, tokenStore, outputAmount, collectorData);
    }

    // =========================================================================
    // Happy Path: Exact Output
    // =========================================================================

    function test_collectTokens_succeeds_exactOutput() public {
        uint120 outputAmount = 100e6;
        uint256 inputAmount = 1e18;

        AuthCaptureEscrow.PaymentInfo memory paymentInfo =
            _createPaymentInfo(payerEOA, outputAmount, address(mockERC20Token));
        address tokenStore = authCaptureEscrow.getTokenStore(paymentInfo.operator);

        // Configure aggregator to produce exactly outputAmount
        aggregator.setOutputAmount(outputAmount);

        SwapCollector.SwapData memory swapData = SwapCollector.SwapData({
            inputToken: address(inputToken),
            maxInputAmount: inputAmount,
            aggregator: address(aggregator),
            aggregatorCalldata: abi.encodeCall(
                MockDEXAggregator.swap, (address(inputToken), address(mockERC20Token), inputAmount, outputAmount)
            )
        });

        bytes memory sig = _signPermit2WitnessTransfer(paymentInfo, swapData, payer_EOA_PK);
        bytes memory collectorData = abi.encode(swapData, sig);

        vm.prank(address(authCaptureEscrow));
        swapCollector.collectTokens(paymentInfo, tokenStore, outputAmount, collectorData);

        assertEq(mockERC20Token.balanceOf(tokenStore), outputAmount, "Token store should have exact output amount");
        assertEq(mockERC20Token.balanceOf(payerEOA), 0, "Payer should have no excess output");
    }

    // =========================================================================
    // Happy Path: Excess Output (Refund to Payer)
    // =========================================================================

    function test_collectTokens_succeeds_excessOutput() public {
        uint120 outputAmount = 100e6;
        uint256 inputAmount = 1e18;
        uint256 excessOutput = 10e6;

        AuthCaptureEscrow.PaymentInfo memory paymentInfo =
            _createPaymentInfo(payerEOA, outputAmount, address(mockERC20Token));
        address tokenStore = authCaptureEscrow.getTokenStore(paymentInfo.operator);

        // Configure aggregator to produce more than required
        aggregator.setOutputAmount(outputAmount + excessOutput);

        SwapCollector.SwapData memory swapData = SwapCollector.SwapData({
            inputToken: address(inputToken),
            maxInputAmount: inputAmount,
            aggregator: address(aggregator),
            aggregatorCalldata: abi.encodeCall(
                MockDEXAggregator.swap, (address(inputToken), address(mockERC20Token), inputAmount, outputAmount)
            )
        });

        bytes memory sig = _signPermit2WitnessTransfer(paymentInfo, swapData, payer_EOA_PK);
        bytes memory collectorData = abi.encode(swapData, sig);

        vm.prank(address(authCaptureEscrow));
        swapCollector.collectTokens(paymentInfo, tokenStore, outputAmount, collectorData);

        assertEq(mockERC20Token.balanceOf(tokenStore), outputAmount, "Token store should have required amount");
        assertEq(mockERC20Token.balanceOf(payerEOA), excessOutput, "Payer should receive excess output");
    }

    // =========================================================================
    // Happy Path: Partial Input Consumed (Refund Unused Input)
    // =========================================================================

    function test_collectTokens_succeeds_partialInputConsumed() public {
        uint120 outputAmount = 100e6;
        uint256 maxInputAmount = 2e18;

        AuthCaptureEscrow.PaymentInfo memory paymentInfo =
            _createPaymentInfo(payerEOA, outputAmount, address(mockERC20Token));
        address tokenStore = authCaptureEscrow.getTokenStore(paymentInfo.operator);

        // The mock aggregator will consume all inputAmount passed to swap(), but we can
        // configure it to produce the exact output. In this test, we simulate partial consumption
        // by configuring the aggregator to take only half and still produce enough output.
        // The mock consumes the full amount passed in calldata, so we pass a smaller amount in calldata
        // but authorize a larger maxInputAmount
        uint256 actualInputUsed = 1e18;
        aggregator.setOutputAmount(outputAmount);

        SwapCollector.SwapData memory swapData = SwapCollector.SwapData({
            inputToken: address(inputToken),
            maxInputAmount: maxInputAmount,
            aggregator: address(aggregator),
            aggregatorCalldata: abi.encodeCall(
                MockDEXAggregator.swap, (address(inputToken), address(mockERC20Token), actualInputUsed, outputAmount)
            )
        });

        uint256 payerInputBefore = inputToken.balanceOf(payerEOA);

        bytes memory sig = _signPermit2WitnessTransfer(paymentInfo, swapData, payer_EOA_PK);
        bytes memory collectorData = abi.encode(swapData, sig);

        vm.prank(address(authCaptureEscrow));
        swapCollector.collectTokens(paymentInfo, tokenStore, outputAmount, collectorData);

        assertEq(mockERC20Token.balanceOf(tokenStore), outputAmount, "Token store should have required output");
        // Payer should get back the unused input (maxInputAmount - actualInputUsed)
        uint256 payerInputAfter = inputToken.balanceOf(payerEOA);
        uint256 unusedInput = maxInputAmount - actualInputUsed;
        assertEq(payerInputAfter, payerInputBefore - maxInputAmount + unusedInput, "Payer should get unused input back");
    }

    // =========================================================================
    // Happy Path: Event Emission
    // =========================================================================

    function test_collectTokens_emitsSwapExecuted() public {
        uint120 outputAmount = 100e6;
        uint256 inputAmount = 1e18;

        AuthCaptureEscrow.PaymentInfo memory paymentInfo =
            _createPaymentInfo(payerEOA, outputAmount, address(mockERC20Token));
        address tokenStore = authCaptureEscrow.getTokenStore(paymentInfo.operator);

        aggregator.setOutputAmount(outputAmount);

        SwapCollector.SwapData memory swapData = SwapCollector.SwapData({
            inputToken: address(inputToken),
            maxInputAmount: inputAmount,
            aggregator: address(aggregator),
            aggregatorCalldata: abi.encodeCall(
                MockDEXAggregator.swap, (address(inputToken), address(mockERC20Token), inputAmount, outputAmount)
            )
        });

        bytes memory sig = _signPermit2WitnessTransfer(paymentInfo, swapData, payer_EOA_PK);
        bytes memory collectorData = abi.encode(swapData, sig);

        vm.prank(address(authCaptureEscrow));
        vm.expectEmit(true, false, false, true);
        emit SwapCollector.SwapExecuted(
            payerEOA, address(inputToken), address(mockERC20Token), inputAmount, outputAmount, outputAmount
        );
        swapCollector.collectTokens(paymentInfo, tokenStore, outputAmount, collectorData);
    }

    // =========================================================================
    // Failure: Swap Reverts
    // =========================================================================

    function test_collectTokens_reverts_swapFailed() public {
        uint120 outputAmount = 100e6;
        uint256 inputAmount = 1e18;

        AuthCaptureEscrow.PaymentInfo memory paymentInfo =
            _createPaymentInfo(payerEOA, outputAmount, address(mockERC20Token));
        address tokenStore = authCaptureEscrow.getTokenStore(paymentInfo.operator);

        // Make aggregator fail
        aggregator.setShouldFail(true);

        SwapCollector.SwapData memory swapData = SwapCollector.SwapData({
            inputToken: address(inputToken),
            maxInputAmount: inputAmount,
            aggregator: address(aggregator),
            aggregatorCalldata: abi.encodeCall(
                MockDEXAggregator.swap, (address(inputToken), address(mockERC20Token), inputAmount, outputAmount)
            )
        });

        bytes memory sig = _signPermit2WitnessTransfer(paymentInfo, swapData, payer_EOA_PK);
        bytes memory collectorData = abi.encode(swapData, sig);

        vm.prank(address(authCaptureEscrow));
        vm.expectRevert(); // SwapFailed with aggregator revert data
        swapCollector.collectTokens(paymentInfo, tokenStore, outputAmount, collectorData);
    }

    // =========================================================================
    // Failure: Slippage Exceeded
    // =========================================================================

    function test_collectTokens_reverts_slippageExceeded() public {
        uint120 outputAmount = 100e6;
        uint256 inputAmount = 1e18;

        AuthCaptureEscrow.PaymentInfo memory paymentInfo =
            _createPaymentInfo(payerEOA, outputAmount, address(mockERC20Token));
        address tokenStore = authCaptureEscrow.getTokenStore(paymentInfo.operator);

        // Configure aggregator to produce less than required
        uint256 insufficientOutput = outputAmount - 1;
        aggregator.setOutputAmount(insufficientOutput);

        SwapCollector.SwapData memory swapData = SwapCollector.SwapData({
            inputToken: address(inputToken),
            maxInputAmount: inputAmount,
            aggregator: address(aggregator),
            aggregatorCalldata: abi.encodeCall(
                MockDEXAggregator.swap, (address(inputToken), address(mockERC20Token), inputAmount, outputAmount)
            )
        });

        bytes memory sig = _signPermit2WitnessTransfer(paymentInfo, swapData, payer_EOA_PK);
        bytes memory collectorData = abi.encode(swapData, sig);

        vm.prank(address(authCaptureEscrow));
        vm.expectRevert(
            abi.encodeWithSelector(SwapCollector.SlippageExceeded.selector, insufficientOutput, outputAmount)
        );
        swapCollector.collectTokens(paymentInfo, tokenStore, outputAmount, collectorData);
    }

    // =========================================================================
    // Failure: Paused
    // =========================================================================

    function test_collectTokens_reverts_whenPaused() public {
        vm.prank(swapCollectorOwner);
        swapCollector.pause();

        uint120 outputAmount = 100e6;
        AuthCaptureEscrow.PaymentInfo memory paymentInfo =
            _createPaymentInfo(payerEOA, outputAmount, address(mockERC20Token));
        address tokenStore = authCaptureEscrow.getTokenStore(paymentInfo.operator);

        SwapCollector.SwapData memory swapData = SwapCollector.SwapData({
            inputToken: address(inputToken),
            maxInputAmount: 1e18,
            aggregator: address(aggregator),
            aggregatorCalldata: hex"deadbeef"
        });

        bytes memory collectorData = abi.encode(swapData, hex"");

        vm.prank(address(authCaptureEscrow));
        vm.expectRevert(abi.encodeWithSelector(Pausable.EnforcedPause.selector));
        swapCollector.collectTokens(paymentInfo, tokenStore, outputAmount, collectorData);
    }

    // =========================================================================
    // ERC-6492: Counterfactual Smart Wallet
    // =========================================================================

    function test_collectTokens_succeeds_withERC6492Signature() public {
        uint120 outputAmount = 100e6;
        uint256 inputAmount = 1e18;

        // Mint input tokens to counterfactual wallet
        inputToken.mint(smartWalletCounterfactual, inputAmount);

        assertEq(smartWalletCounterfactual.code.length, 0, "Smart wallet should not be deployed yet");

        AuthCaptureEscrow.PaymentInfo memory paymentInfo =
            _createPaymentInfo(smartWalletCounterfactual, outputAmount, address(mockERC20Token));
        address tokenStore = authCaptureEscrow.getTokenStore(paymentInfo.operator);

        aggregator.setOutputAmount(outputAmount);

        SwapCollector.SwapData memory swapData = SwapCollector.SwapData({
            inputToken: address(inputToken),
            maxInputAmount: inputAmount,
            aggregator: address(aggregator),
            aggregatorCalldata: abi.encodeCall(
                MockDEXAggregator.swap, (address(inputToken), address(mockERC20Token), inputAmount, outputAmount)
            )
        });

        bytes memory sig =
            _signPermit2WitnessTransferWithERC6492(paymentInfo, swapData, COUNTERFACTUAL_WALLET_OWNER_PK, 0);
        bytes memory collectorData = abi.encode(swapData, sig);

        vm.prank(address(authCaptureEscrow));
        swapCollector.collectTokens(paymentInfo, tokenStore, outputAmount, collectorData);

        assertEq(mockERC20Token.balanceOf(tokenStore), outputAmount, "Token store should have required output");
    }

    // =========================================================================
    // Integration: Full Flow through AuthCaptureEscrow.authorize()
    // =========================================================================

    function test_integration_authorizeWithSwapCollector() public {
        uint120 outputAmount = 100e6;
        uint256 inputAmount = 1e18;

        AuthCaptureEscrow.PaymentInfo memory paymentInfo =
            _createPaymentInfo(payerEOA, outputAmount, address(mockERC20Token));

        aggregator.setOutputAmount(outputAmount);

        SwapCollector.SwapData memory swapData = SwapCollector.SwapData({
            inputToken: address(inputToken),
            maxInputAmount: inputAmount,
            aggregator: address(aggregator),
            aggregatorCalldata: abi.encodeCall(
                MockDEXAggregator.swap, (address(inputToken), address(mockERC20Token), inputAmount, outputAmount)
            )
        });

        bytes memory sig = _signPermit2WitnessTransfer(paymentInfo, swapData, payer_EOA_PK);
        bytes memory collectorData = abi.encode(swapData, sig);

        vm.prank(operator);
        authCaptureEscrow.authorize(paymentInfo, outputAmount, address(swapCollector), collectorData);

        // Verify payment state
        bytes32 paymentHash = authCaptureEscrow.getHash(paymentInfo);
        (bool hasCollected, uint120 capturable, uint120 refundable) = authCaptureEscrow.paymentState(paymentHash);
        assertTrue(hasCollected, "Payment should be collected");
        assertEq(capturable, outputAmount, "Capturable amount should match");
        assertEq(refundable, 0, "Refundable should be zero");
    }

    // =========================================================================
    // Fuzz Tests: Happy Path with Variable Amounts
    // =========================================================================

    function test_fuzz_collectTokens_exactOutput(uint120 outputAmount, uint256 inputAmount) public {
        vm.assume(outputAmount > 0);
        vm.assume(inputAmount > 0 && inputAmount <= 1000e18);

        // Mint sufficient input tokens
        inputToken.mint(payerEOA, inputAmount);

        AuthCaptureEscrow.PaymentInfo memory paymentInfo =
            _createPaymentInfo(payerEOA, outputAmount, address(mockERC20Token));
        address tokenStore = authCaptureEscrow.getTokenStore(paymentInfo.operator);

        // Configure aggregator to produce exactly outputAmount
        aggregator.setOutputAmount(outputAmount);

        SwapCollector.SwapData memory swapData = SwapCollector.SwapData({
            inputToken: address(inputToken),
            maxInputAmount: inputAmount,
            aggregator: address(aggregator),
            aggregatorCalldata: abi.encodeCall(
                MockDEXAggregator.swap, (address(inputToken), address(mockERC20Token), inputAmount, outputAmount)
            )
        });

        bytes memory sig = _signPermit2WitnessTransfer(paymentInfo, swapData, payer_EOA_PK);
        bytes memory collectorData = abi.encode(swapData, sig);

        vm.prank(address(authCaptureEscrow));
        swapCollector.collectTokens(paymentInfo, tokenStore, outputAmount, collectorData);

        assertEq(mockERC20Token.balanceOf(tokenStore), outputAmount, "Token store should have exact output amount");
        assertEq(mockERC20Token.balanceOf(payerEOA), 0, "Payer should have no excess output");
    }

    function test_fuzz_collectTokens_excessOutputRefunded(
        uint120 outputAmount,
        uint120 excessOutput,
        uint256 inputAmount
    ) public {
        vm.assume(outputAmount > 0);
        vm.assume(excessOutput > 0);
        vm.assume(inputAmount > 0 && inputAmount <= 1000e18);
        // Prevent overflow in outputAmount + excessOutput
        vm.assume(uint256(outputAmount) + uint256(excessOutput) <= type(uint256).max);

        inputToken.mint(payerEOA, inputAmount);

        AuthCaptureEscrow.PaymentInfo memory paymentInfo =
            _createPaymentInfo(payerEOA, outputAmount, address(mockERC20Token));
        address tokenStore = authCaptureEscrow.getTokenStore(paymentInfo.operator);

        aggregator.setOutputAmount(uint256(outputAmount) + uint256(excessOutput));

        SwapCollector.SwapData memory swapData = SwapCollector.SwapData({
            inputToken: address(inputToken),
            maxInputAmount: inputAmount,
            aggregator: address(aggregator),
            aggregatorCalldata: abi.encodeCall(
                MockDEXAggregator.swap, (address(inputToken), address(mockERC20Token), inputAmount, outputAmount)
            )
        });

        bytes memory sig = _signPermit2WitnessTransfer(paymentInfo, swapData, payer_EOA_PK);
        bytes memory collectorData = abi.encode(swapData, sig);

        vm.prank(address(authCaptureEscrow));
        swapCollector.collectTokens(paymentInfo, tokenStore, outputAmount, collectorData);

        assertEq(mockERC20Token.balanceOf(tokenStore), outputAmount, "Token store should have required amount");
        assertEq(mockERC20Token.balanceOf(payerEOA), excessOutput, "Payer should receive excess output");
    }

    function test_fuzz_collectTokens_partialInputRefunded(uint120 outputAmount, uint256 maxInput, uint256 actualInput)
        public
    {
        vm.assume(outputAmount > 0);
        vm.assume(maxInput > 0 && maxInput <= 1000e18);
        vm.assume(actualInput > 0 && actualInput < maxInput);

        inputToken.mint(payerEOA, maxInput);

        AuthCaptureEscrow.PaymentInfo memory paymentInfo =
            _createPaymentInfo(payerEOA, outputAmount, address(mockERC20Token));
        address tokenStore = authCaptureEscrow.getTokenStore(paymentInfo.operator);

        aggregator.setOutputAmount(outputAmount);

        SwapCollector.SwapData memory swapData = SwapCollector.SwapData({
            inputToken: address(inputToken),
            maxInputAmount: maxInput,
            aggregator: address(aggregator),
            aggregatorCalldata: abi.encodeCall(
                MockDEXAggregator.swap, (address(inputToken), address(mockERC20Token), actualInput, outputAmount)
            )
        });

        uint256 payerInputBefore = inputToken.balanceOf(payerEOA);

        bytes memory sig = _signPermit2WitnessTransfer(paymentInfo, swapData, payer_EOA_PK);
        bytes memory collectorData = abi.encode(swapData, sig);

        vm.prank(address(authCaptureEscrow));
        swapCollector.collectTokens(paymentInfo, tokenStore, outputAmount, collectorData);

        assertEq(mockERC20Token.balanceOf(tokenStore), outputAmount, "Token store should have required output");
        // Payer gets back unused input: maxInput was pulled, actualInput was consumed, so (maxInput - actualInput) refunded
        uint256 expectedPayerInput = payerInputBefore - actualInput;
        assertEq(inputToken.balanceOf(payerEOA), expectedPayerInput, "Payer should get unused input back");
    }

    // =========================================================================
    // Fuzz Tests: Slippage Enforcement
    // =========================================================================

    function test_fuzz_collectTokens_reverts_slippageExceeded(uint120 outputAmount, uint120 shortfall) public {
        vm.assume(outputAmount > 1);
        vm.assume(shortfall > 0 && shortfall < outputAmount);
        uint256 inputAmount = 1e18;
        uint256 insufficientOutput = uint256(outputAmount) - uint256(shortfall);

        inputToken.mint(payerEOA, inputAmount);

        AuthCaptureEscrow.PaymentInfo memory paymentInfo =
            _createPaymentInfo(payerEOA, outputAmount, address(mockERC20Token));
        address tokenStore = authCaptureEscrow.getTokenStore(paymentInfo.operator);

        aggregator.setOutputAmount(insufficientOutput);

        SwapCollector.SwapData memory swapData = SwapCollector.SwapData({
            inputToken: address(inputToken),
            maxInputAmount: inputAmount,
            aggregator: address(aggregator),
            aggregatorCalldata: abi.encodeCall(
                MockDEXAggregator.swap, (address(inputToken), address(mockERC20Token), inputAmount, outputAmount)
            )
        });

        bytes memory sig = _signPermit2WitnessTransfer(paymentInfo, swapData, payer_EOA_PK);
        bytes memory collectorData = abi.encode(swapData, sig);

        vm.prank(address(authCaptureEscrow));
        vm.expectRevert(
            abi.encodeWithSelector(SwapCollector.SlippageExceeded.selector, insufficientOutput, outputAmount)
        );
        swapCollector.collectTokens(paymentInfo, tokenStore, outputAmount, collectorData);
    }

    // =========================================================================
    // Fuzz Tests: Access Control
    // =========================================================================

    function test_fuzz_collectTokens_reverts_whenCalledByNonAuthCaptureEscrow(address caller) public {
        vm.assume(caller != address(authCaptureEscrow));
        vm.assume(caller != address(0));

        uint120 outputAmount = 100e6;
        AuthCaptureEscrow.PaymentInfo memory paymentInfo =
            _createPaymentInfo(payerEOA, outputAmount, address(mockERC20Token));
        address tokenStore = authCaptureEscrow.getTokenStore(paymentInfo.operator);

        vm.prank(caller);
        vm.expectRevert(abi.encodeWithSelector(TokenCollector.OnlyAuthCaptureEscrow.selector));
        swapCollector.collectTokens(paymentInfo, tokenStore, outputAmount, "");
    }

    function test_fuzz_whitelistToken_reverts_whenCalledByNonOwner(address caller) public {
        vm.assume(caller != swapCollectorOwner);
        vm.assume(caller != address(0));

        vm.prank(caller);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, caller));
        swapCollector.whitelistToken(address(0xBEEF), true);
    }

    function test_fuzz_whitelistAggregator_reverts_whenCalledByNonOwner(address caller) public {
        vm.assume(caller != swapCollectorOwner);
        vm.assume(caller != address(0));

        vm.prank(caller);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, caller));
        swapCollector.whitelistAggregator(address(0xCAFE), true);
    }

    function test_fuzz_pause_reverts_whenCalledByNonOwner(address caller) public {
        vm.assume(caller != swapCollectorOwner);
        vm.assume(caller != address(0));

        vm.prank(caller);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, caller));
        swapCollector.pause();
    }

    function test_fuzz_emergencyWithdraw_reverts_whenCalledByNonOwner(address caller) public {
        vm.assume(caller != swapCollectorOwner);
        vm.assume(caller != address(0));

        vm.prank(caller);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, caller));
        swapCollector.emergencyWithdraw(address(inputToken), caller, 1);
    }

    // =========================================================================
    // Fuzz Tests: Emergency Withdraw
    // =========================================================================

    function test_fuzz_emergencyWithdraw_succeeds(uint256 amount) public {
        vm.assume(amount > 0 && amount <= 1000e18);

        inputToken.mint(address(swapCollector), amount);

        vm.prank(swapCollectorOwner);
        swapCollector.emergencyWithdraw(address(inputToken), swapCollectorOwner, amount);

        assertEq(inputToken.balanceOf(swapCollectorOwner), amount);
        assertEq(inputToken.balanceOf(address(swapCollector)), 0);
    }

    // =========================================================================
    // Fuzz Tests: Token Store Receives Exact Amount
    // =========================================================================

    function test_fuzz_tokenStoreReceivesExactAmount(uint120 outputAmount, uint120 excessOutput) public {
        vm.assume(outputAmount > 0);
        vm.assume(uint256(outputAmount) + uint256(excessOutput) <= type(uint256).max);
        uint256 inputAmount = 1e18;

        inputToken.mint(payerEOA, inputAmount);

        AuthCaptureEscrow.PaymentInfo memory paymentInfo =
            _createPaymentInfo(payerEOA, outputAmount, address(mockERC20Token));
        address tokenStore = authCaptureEscrow.getTokenStore(paymentInfo.operator);

        uint256 totalOutput = uint256(outputAmount) + uint256(excessOutput);
        aggregator.setOutputAmount(totalOutput);

        SwapCollector.SwapData memory swapData = SwapCollector.SwapData({
            inputToken: address(inputToken),
            maxInputAmount: inputAmount,
            aggregator: address(aggregator),
            aggregatorCalldata: abi.encodeCall(
                MockDEXAggregator.swap, (address(inputToken), address(mockERC20Token), inputAmount, outputAmount)
            )
        });

        bytes memory sig = _signPermit2WitnessTransfer(paymentInfo, swapData, payer_EOA_PK);
        bytes memory collectorData = abi.encode(swapData, sig);

        uint256 storeBefore = mockERC20Token.balanceOf(tokenStore);

        vm.prank(address(authCaptureEscrow));
        swapCollector.collectTokens(paymentInfo, tokenStore, outputAmount, collectorData);

        // CRITICAL INVARIANT: token store receives EXACTLY the requested amount
        assertEq(
            mockERC20Token.balanceOf(tokenStore) - storeBefore,
            outputAmount,
            "Token store must receive EXACTLY the requested amount"
        );
    }

    // =========================================================================
    // Fuzz Tests: No Token Leakage (Conservation of Value)
    // =========================================================================

    function test_fuzz_noOutputTokenLeakage(uint120 outputAmount, uint120 excessOutput) public {
        vm.assume(outputAmount > 0);
        vm.assume(uint256(outputAmount) + uint256(excessOutput) <= type(uint256).max);
        uint256 inputAmount = 1e18;

        inputToken.mint(payerEOA, inputAmount);

        AuthCaptureEscrow.PaymentInfo memory paymentInfo =
            _createPaymentInfo(payerEOA, outputAmount, address(mockERC20Token));
        address tokenStore = authCaptureEscrow.getTokenStore(paymentInfo.operator);

        uint256 totalOutput = uint256(outputAmount) + uint256(excessOutput);
        aggregator.setOutputAmount(totalOutput);

        SwapCollector.SwapData memory swapData = SwapCollector.SwapData({
            inputToken: address(inputToken),
            maxInputAmount: inputAmount,
            aggregator: address(aggregator),
            aggregatorCalldata: abi.encodeCall(
                MockDEXAggregator.swap, (address(inputToken), address(mockERC20Token), inputAmount, outputAmount)
            )
        });

        bytes memory sig = _signPermit2WitnessTransfer(paymentInfo, swapData, payer_EOA_PK);
        bytes memory collectorData = abi.encode(swapData, sig);

        uint256 collectorOutputBefore = mockERC20Token.balanceOf(address(swapCollector));

        vm.prank(address(authCaptureEscrow));
        swapCollector.collectTokens(paymentInfo, tokenStore, outputAmount, collectorData);

        // INVARIANT: no output tokens should remain stuck in the collector
        assertEq(
            mockERC20Token.balanceOf(address(swapCollector)),
            collectorOutputBefore,
            "No output tokens should be stuck in collector"
        );
    }

    function test_fuzz_noInputTokenLeakage(uint120 outputAmount, uint256 maxInput, uint256 actualInput) public {
        vm.assume(outputAmount > 0);
        vm.assume(maxInput > 0 && maxInput <= 1000e18);
        vm.assume(actualInput > 0 && actualInput <= maxInput);

        inputToken.mint(payerEOA, maxInput);

        AuthCaptureEscrow.PaymentInfo memory paymentInfo =
            _createPaymentInfo(payerEOA, outputAmount, address(mockERC20Token));
        address tokenStore = authCaptureEscrow.getTokenStore(paymentInfo.operator);

        aggregator.setOutputAmount(outputAmount);

        SwapCollector.SwapData memory swapData = SwapCollector.SwapData({
            inputToken: address(inputToken),
            maxInputAmount: maxInput,
            aggregator: address(aggregator),
            aggregatorCalldata: abi.encodeCall(
                MockDEXAggregator.swap, (address(inputToken), address(mockERC20Token), actualInput, outputAmount)
            )
        });

        bytes memory sig = _signPermit2WitnessTransfer(paymentInfo, swapData, payer_EOA_PK);
        bytes memory collectorData = abi.encode(swapData, sig);

        uint256 collectorInputBefore = inputToken.balanceOf(address(swapCollector));

        vm.prank(address(authCaptureEscrow));
        swapCollector.collectTokens(paymentInfo, tokenStore, outputAmount, collectorData);

        // INVARIANT: no input tokens should remain stuck in the collector
        assertEq(
            inputToken.balanceOf(address(swapCollector)),
            collectorInputBefore,
            "No input tokens should be stuck in collector"
        );
    }

    // =========================================================================
    // Integration: Full Flow through AuthCaptureEscrow.charge()
    // =========================================================================

    function test_integration_chargeWithSwapCollector() public {
        uint120 outputAmount = 100e6;
        uint256 inputAmount = 1e18;

        AuthCaptureEscrow.PaymentInfo memory paymentInfo =
            _createPaymentInfo(payerEOA, outputAmount, address(mockERC20Token));

        aggregator.setOutputAmount(outputAmount);

        SwapCollector.SwapData memory swapData = SwapCollector.SwapData({
            inputToken: address(inputToken),
            maxInputAmount: inputAmount,
            aggregator: address(aggregator),
            aggregatorCalldata: abi.encodeCall(
                MockDEXAggregator.swap, (address(inputToken), address(mockERC20Token), inputAmount, outputAmount)
            )
        });

        bytes memory sig = _signPermit2WitnessTransfer(paymentInfo, swapData, payer_EOA_PK);
        bytes memory collectorData = abi.encode(swapData, sig);

        uint256 receiverBefore = mockERC20Token.balanceOf(receiver);
        uint256 feeReceiverBefore = mockERC20Token.balanceOf(feeReceiver);

        vm.prank(operator);
        authCaptureEscrow.charge(paymentInfo, outputAmount, address(swapCollector), collectorData, FEE_BPS, feeReceiver);

        // Verify payment state: charge sets refundableAmount, capturableAmount stays 0
        bytes32 paymentHash = authCaptureEscrow.getHash(paymentInfo);
        (bool hasCollected, uint120 capturable, uint120 refundable) = authCaptureEscrow.paymentState(paymentHash);
        assertTrue(hasCollected, "Payment should be collected");
        assertEq(capturable, 0, "Capturable should be zero after charge");
        assertEq(refundable, outputAmount, "Refundable should equal charged amount");

        // Verify receiver got payment minus fee
        uint256 expectedFee = uint256(outputAmount) * FEE_BPS / 10_000;
        uint256 expectedReceiverAmount = uint256(outputAmount) - expectedFee;
        assertEq(
            mockERC20Token.balanceOf(receiver) - receiverBefore,
            expectedReceiverAmount,
            "Receiver should get amount minus fee"
        );
        assertEq(mockERC20Token.balanceOf(feeReceiver) - feeReceiverBefore, expectedFee, "Fee receiver should get fee");
    }

    function test_integration_chargeWithSwapCollector_excessOutputRefundedToPayer() public {
        uint120 outputAmount = 100e6;
        uint256 inputAmount = 1e18;
        uint256 excessOutput = 10e6;

        AuthCaptureEscrow.PaymentInfo memory paymentInfo =
            _createPaymentInfo(payerEOA, outputAmount, address(mockERC20Token));

        // Aggregator produces more output than needed
        aggregator.setOutputAmount(outputAmount + excessOutput);

        SwapCollector.SwapData memory swapData = SwapCollector.SwapData({
            inputToken: address(inputToken),
            maxInputAmount: inputAmount,
            aggregator: address(aggregator),
            aggregatorCalldata: abi.encodeCall(
                MockDEXAggregator.swap, (address(inputToken), address(mockERC20Token), inputAmount, outputAmount)
            )
        });

        bytes memory sig = _signPermit2WitnessTransfer(paymentInfo, swapData, payer_EOA_PK);
        bytes memory collectorData = abi.encode(swapData, sig);

        uint256 payerOutputBefore = mockERC20Token.balanceOf(payerEOA);

        vm.prank(operator);
        authCaptureEscrow.charge(paymentInfo, outputAmount, address(swapCollector), collectorData, FEE_BPS, feeReceiver);

        // Payer gets excess output tokens refunded by SwapCollector
        assertEq(
            mockERC20Token.balanceOf(payerEOA) - payerOutputBefore, excessOutput, "Payer should get excess output back"
        );
    }

    function test_integration_chargeWithSwapCollector_partialInputRefundedToPayer() public {
        uint120 outputAmount = 100e6;
        uint256 maxInputAmount = 2e18;
        uint256 actualInputUsed = 1e18;

        AuthCaptureEscrow.PaymentInfo memory paymentInfo =
            _createPaymentInfo(payerEOA, outputAmount, address(mockERC20Token));

        aggregator.setOutputAmount(outputAmount);

        SwapCollector.SwapData memory swapData = SwapCollector.SwapData({
            inputToken: address(inputToken),
            maxInputAmount: maxInputAmount,
            aggregator: address(aggregator),
            aggregatorCalldata: abi.encodeCall(
                MockDEXAggregator.swap, (address(inputToken), address(mockERC20Token), actualInputUsed, outputAmount)
            )
        });

        uint256 payerInputBefore = inputToken.balanceOf(payerEOA);

        bytes memory sig = _signPermit2WitnessTransfer(paymentInfo, swapData, payer_EOA_PK);
        bytes memory collectorData = abi.encode(swapData, sig);

        vm.prank(operator);
        authCaptureEscrow.charge(paymentInfo, outputAmount, address(swapCollector), collectorData, FEE_BPS, feeReceiver);

        // Payer should only lose the actualInputUsed, rest refunded
        assertEq(
            inputToken.balanceOf(payerEOA), payerInputBefore - actualInputUsed, "Payer should get unused input back"
        );
    }

    // =========================================================================
    // Approval Reset Verification
    // =========================================================================

    function test_collectTokens_resetsAggregatorApprovalAfterSwap() public {
        uint120 outputAmount = 100e6;
        uint256 inputAmount = 1e18;

        AuthCaptureEscrow.PaymentInfo memory paymentInfo =
            _createPaymentInfo(payerEOA, outputAmount, address(mockERC20Token));
        address tokenStore = authCaptureEscrow.getTokenStore(paymentInfo.operator);

        aggregator.setOutputAmount(outputAmount);

        SwapCollector.SwapData memory swapData = SwapCollector.SwapData({
            inputToken: address(inputToken),
            maxInputAmount: inputAmount,
            aggregator: address(aggregator),
            aggregatorCalldata: abi.encodeCall(
                MockDEXAggregator.swap, (address(inputToken), address(mockERC20Token), inputAmount, outputAmount)
            )
        });

        bytes memory sig = _signPermit2WitnessTransfer(paymentInfo, swapData, payer_EOA_PK);
        bytes memory collectorData = abi.encode(swapData, sig);

        vm.prank(address(authCaptureEscrow));
        swapCollector.collectTokens(paymentInfo, tokenStore, outputAmount, collectorData);

        // Aggregator approval must be reset to 0 after swap
        assertEq(
            inputToken.allowance(address(swapCollector), address(aggregator)),
            0,
            "Aggregator approval must be zero after swap"
        );
    }

    // =========================================================================
    // Pre-existing Collector Balance
    // =========================================================================

    function test_collectTokens_succeeds_withPreExistingOutputBalance() public {
        uint120 outputAmount = 100e6;
        uint256 inputAmount = 1e18;

        // Simulate stuck output tokens in collector from a previous emergency or edge case
        uint256 stuckAmount = 50e6;
        mockERC20Token.mint(address(swapCollector), stuckAmount);

        AuthCaptureEscrow.PaymentInfo memory paymentInfo =
            _createPaymentInfo(payerEOA, outputAmount, address(mockERC20Token));
        address tokenStore = authCaptureEscrow.getTokenStore(paymentInfo.operator);

        aggregator.setOutputAmount(outputAmount);

        SwapCollector.SwapData memory swapData = SwapCollector.SwapData({
            inputToken: address(inputToken),
            maxInputAmount: inputAmount,
            aggregator: address(aggregator),
            aggregatorCalldata: abi.encodeCall(
                MockDEXAggregator.swap, (address(inputToken), address(mockERC20Token), inputAmount, outputAmount)
            )
        });

        bytes memory sig = _signPermit2WitnessTransfer(paymentInfo, swapData, payer_EOA_PK);
        bytes memory collectorData = abi.encode(swapData, sig);

        vm.prank(address(authCaptureEscrow));
        swapCollector.collectTokens(paymentInfo, tokenStore, outputAmount, collectorData);

        // Token store should get exactly the required amount
        assertEq(mockERC20Token.balanceOf(tokenStore), outputAmount, "Token store should have required amount");
        // Pre-existing stuck balance should remain untouched
        assertEq(
            mockERC20Token.balanceOf(address(swapCollector)),
            stuckAmount,
            "Pre-existing balance should remain in collector"
        );
    }

    function test_collectTokens_succeeds_withPreExistingInputBalance() public {
        uint120 outputAmount = 100e6;
        uint256 inputAmount = 1e18;

        // Simulate stuck input tokens in collector
        uint256 stuckAmount = 5e18;
        inputToken.mint(address(swapCollector), stuckAmount);

        AuthCaptureEscrow.PaymentInfo memory paymentInfo =
            _createPaymentInfo(payerEOA, outputAmount, address(mockERC20Token));
        address tokenStore = authCaptureEscrow.getTokenStore(paymentInfo.operator);

        aggregator.setOutputAmount(outputAmount);

        SwapCollector.SwapData memory swapData = SwapCollector.SwapData({
            inputToken: address(inputToken),
            maxInputAmount: inputAmount,
            aggregator: address(aggregator),
            aggregatorCalldata: abi.encodeCall(
                MockDEXAggregator.swap, (address(inputToken), address(mockERC20Token), inputAmount, outputAmount)
            )
        });

        bytes memory sig = _signPermit2WitnessTransfer(paymentInfo, swapData, payer_EOA_PK);
        bytes memory collectorData = abi.encode(swapData, sig);

        vm.prank(address(authCaptureEscrow));
        swapCollector.collectTokens(paymentInfo, tokenStore, outputAmount, collectorData);

        // Pre-existing stuck input balance should remain untouched (not refunded to payer)
        assertEq(
            inputToken.balanceOf(address(swapCollector)),
            stuckAmount,
            "Pre-existing input balance should remain in collector"
        );
        // Payer should not get pre-existing tokens, only their own unused input
        assertEq(mockERC20Token.balanceOf(tokenStore), outputAmount, "Token store should have required output");
    }

    // =========================================================================
    // Fuzz Tests: Integration through AuthCaptureEscrow (authorize + charge)
    // =========================================================================

    function test_fuzz_integration_authorizeWithSwapCollector(uint120 outputAmount) public {
        vm.assume(outputAmount > 0);
        uint256 inputAmount = 1e18;

        inputToken.mint(payerEOA, inputAmount);

        AuthCaptureEscrow.PaymentInfo memory paymentInfo =
            _createPaymentInfo(payerEOA, outputAmount, address(mockERC20Token));

        aggregator.setOutputAmount(outputAmount);

        SwapCollector.SwapData memory swapData = SwapCollector.SwapData({
            inputToken: address(inputToken),
            maxInputAmount: inputAmount,
            aggregator: address(aggregator),
            aggregatorCalldata: abi.encodeCall(
                MockDEXAggregator.swap, (address(inputToken), address(mockERC20Token), inputAmount, outputAmount)
            )
        });

        bytes memory sig = _signPermit2WitnessTransfer(paymentInfo, swapData, payer_EOA_PK);
        bytes memory collectorData = abi.encode(swapData, sig);

        vm.prank(operator);
        authCaptureEscrow.authorize(paymentInfo, outputAmount, address(swapCollector), collectorData);

        bytes32 paymentHash = authCaptureEscrow.getHash(paymentInfo);
        (bool hasCollected, uint120 capturable, uint120 refundable) = authCaptureEscrow.paymentState(paymentHash);
        assertTrue(hasCollected, "Payment should be collected");
        assertEq(capturable, outputAmount, "Capturable amount should match");
        assertEq(refundable, 0, "Refundable should be zero");
    }

    function test_fuzz_integration_chargeWithSwapCollector(uint120 outputAmount) public {
        vm.assume(outputAmount > 0);
        uint256 inputAmount = 1e18;

        inputToken.mint(payerEOA, inputAmount);

        AuthCaptureEscrow.PaymentInfo memory paymentInfo =
            _createPaymentInfo(payerEOA, outputAmount, address(mockERC20Token));

        aggregator.setOutputAmount(outputAmount);

        SwapCollector.SwapData memory swapData = SwapCollector.SwapData({
            inputToken: address(inputToken),
            maxInputAmount: inputAmount,
            aggregator: address(aggregator),
            aggregatorCalldata: abi.encodeCall(
                MockDEXAggregator.swap, (address(inputToken), address(mockERC20Token), inputAmount, outputAmount)
            )
        });

        bytes memory sig = _signPermit2WitnessTransfer(paymentInfo, swapData, payer_EOA_PK);
        bytes memory collectorData = abi.encode(swapData, sig);

        uint256 receiverBefore = mockERC20Token.balanceOf(receiver);
        uint256 feeReceiverBefore = mockERC20Token.balanceOf(feeReceiver);

        vm.prank(operator);
        authCaptureEscrow.charge(paymentInfo, outputAmount, address(swapCollector), collectorData, FEE_BPS, feeReceiver);

        // Verify payment state
        bytes32 paymentHash = authCaptureEscrow.getHash(paymentInfo);
        (bool hasCollected, uint120 capturable, uint120 refundable) = authCaptureEscrow.paymentState(paymentHash);
        assertTrue(hasCollected, "Payment should be collected");
        assertEq(capturable, 0, "Capturable should be zero after charge");
        assertEq(refundable, outputAmount, "Refundable should equal charged amount");

        // Verify fund distribution
        uint256 expectedFee = uint256(outputAmount) * FEE_BPS / 10_000;
        uint256 expectedReceiverAmount = uint256(outputAmount) - expectedFee;
        assertEq(
            mockERC20Token.balanceOf(receiver) - receiverBefore,
            expectedReceiverAmount,
            "Receiver should get amount minus fee"
        );
        assertEq(mockERC20Token.balanceOf(feeReceiver) - feeReceiverBefore, expectedFee, "Fee receiver should get fee");
    }

    function test_fuzz_integration_chargeConservesValue(uint120 outputAmount, uint120 excessOutput) public {
        vm.assume(outputAmount > 0);
        vm.assume(uint256(outputAmount) + uint256(excessOutput) <= type(uint256).max);
        uint256 inputAmount = 1e18;

        inputToken.mint(payerEOA, inputAmount);

        AuthCaptureEscrow.PaymentInfo memory paymentInfo =
            _createPaymentInfo(payerEOA, outputAmount, address(mockERC20Token));

        uint256 totalOutput = uint256(outputAmount) + uint256(excessOutput);
        aggregator.setOutputAmount(totalOutput);

        SwapCollector.SwapData memory swapData = SwapCollector.SwapData({
            inputToken: address(inputToken),
            maxInputAmount: inputAmount,
            aggregator: address(aggregator),
            aggregatorCalldata: abi.encodeCall(
                MockDEXAggregator.swap, (address(inputToken), address(mockERC20Token), inputAmount, outputAmount)
            )
        });

        bytes memory sig = _signPermit2WitnessTransfer(paymentInfo, swapData, payer_EOA_PK);
        bytes memory collectorData = abi.encode(swapData, sig);

        uint256 payerBefore = mockERC20Token.balanceOf(payerEOA);
        uint256 receiverBefore = mockERC20Token.balanceOf(receiver);
        uint256 feeReceiverBefore = mockERC20Token.balanceOf(feeReceiver);
        uint256 collectorBefore = mockERC20Token.balanceOf(address(swapCollector));

        vm.prank(operator);
        authCaptureEscrow.charge(paymentInfo, outputAmount, address(swapCollector), collectorData, FEE_BPS, feeReceiver);

        // Total output minted by aggregator must equal sum of all recipients
        uint256 payerGain = mockERC20Token.balanceOf(payerEOA) - payerBefore;
        uint256 receiverGain = mockERC20Token.balanceOf(receiver) - receiverBefore;
        uint256 feeReceiverGain = mockERC20Token.balanceOf(feeReceiver) - feeReceiverBefore;
        uint256 collectorGain = mockERC20Token.balanceOf(address(swapCollector)) - collectorBefore;

        assertEq(
            payerGain + receiverGain + feeReceiverGain + collectorGain,
            totalOutput,
            "All minted output tokens must be accounted for"
        );
        assertEq(collectorGain, 0, "No tokens should remain in collector");
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    /// @notice Sign a Permit2 witness transfer for the SwapCollector
    function _signPermit2WitnessTransfer(
        AuthCaptureEscrow.PaymentInfo memory paymentInfo,
        SwapCollector.SwapData memory swapData,
        uint256 privateKey
    ) internal view returns (bytes memory) {
        bytes32 nonce = _getHashPayerAgnostic(paymentInfo);

        // Build witness hash
        bytes32 witness =
            keccak256(abi.encode(SWAP_WITNESS_TYPEHASH, swapData.aggregator, keccak256(swapData.aggregatorCalldata)));

        // Build the full typehash for PermitWitnessTransferFrom
        bytes32 typeHash =
            keccak256(abi.encodePacked(_PERMIT_TRANSFER_FROM_WITNESS_TYPEHASH_STUB, SWAP_WITNESS_TYPE_STRING));

        bytes32 tokenPermissionsHash =
            keccak256(abi.encode(_TOKEN_PERMISSIONS_TYPEHASH_LOCAL, swapData.inputToken, swapData.maxInputAmount));

        bytes32 permitHash = keccak256(
            abi.encode(
                typeHash,
                tokenPermissionsHash,
                address(swapCollector),
                uint256(nonce),
                paymentInfo.preApprovalExpiry,
                witness
            )
        );

        bytes32 domainSeparator = IPermit2(permit2).DOMAIN_SEPARATOR();
        bytes32 msgHash = keccak256(abi.encodePacked("\x19\x01", domainSeparator, permitHash));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, msgHash);
        return abi.encodePacked(r, s, v);
    }

    /// @notice Compute the Permit2 witness transfer digest for swap
    function _getPermit2WitnessDigest(
        AuthCaptureEscrow.PaymentInfo memory paymentInfo,
        SwapCollector.SwapData memory swapData
    ) internal view returns (bytes32) {
        bytes32 witness =
            keccak256(abi.encode(SWAP_WITNESS_TYPEHASH, swapData.aggregator, keccak256(swapData.aggregatorCalldata)));

        bytes32 typeHash =
            keccak256(abi.encodePacked(_PERMIT_TRANSFER_FROM_WITNESS_TYPEHASH_STUB, SWAP_WITNESS_TYPE_STRING));

        bytes32 tokenPermissionsHash =
            keccak256(abi.encode(_TOKEN_PERMISSIONS_TYPEHASH_LOCAL, swapData.inputToken, swapData.maxInputAmount));

        bytes32 permitHash = keccak256(
            abi.encode(
                typeHash,
                tokenPermissionsHash,
                address(swapCollector),
                uint256(_getHashPayerAgnostic(paymentInfo)),
                paymentInfo.preApprovalExpiry,
                witness
            )
        );

        bytes32 domainSeparator = IPermit2(permit2).DOMAIN_SEPARATOR();
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, permitHash));
    }

    /// @notice Sign a Permit2 witness transfer wrapped in ERC-6492 for counterfactual smart wallets
    function _signPermit2WitnessTransferWithERC6492(
        AuthCaptureEscrow.PaymentInfo memory paymentInfo,
        SwapCollector.SwapData memory swapData,
        uint256 ownerPk,
        uint256 ownerIndex
    ) internal view returns (bytes memory) {
        bytes32 permit2Digest = _getPermit2WitnessDigest(paymentInfo, swapData);

        // Wrap in smart wallet domain
        bytes32 smartWalletDomainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("Coinbase Smart Wallet")),
                keccak256(bytes("1")),
                block.chainid,
                paymentInfo.payer
            )
        );

        bytes32 messageHash =
            keccak256(abi.encode(keccak256("CoinbaseSmartWalletMessage(bytes32 hash)"), permit2Digest));
        bytes32 finalHash = keccak256(abi.encodePacked("\x19\x01", smartWalletDomainSeparator, messageHash));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, finalHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Wrap in smart wallet SignatureWrapper
        bytes memory wrappedSignature = abi.encode(CoinbaseSmartWallet.SignatureWrapper(ownerIndex, signature));

        // Wrap in ERC-6492
        return _wrapWithERC6492(wrappedSignature, ownerPk, ownerIndex);
    }
}
