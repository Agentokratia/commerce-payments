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
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Ownable2Step, Ownable} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ReentrancyGuardTransient} from "solady/utils/ReentrancyGuardTransient.sol";
import {ISignatureTransfer} from "permit2/interfaces/ISignatureTransfer.sol";

import {TokenCollector} from "./TokenCollector.sol";
import {ERC6492SignatureHandler} from "./ERC6492SignatureHandler.sol";
import {AuthCaptureEscrow} from "../AuthCaptureEscrow.sol";

/// @dev EIP-712 type string for the SwapWitness struct, appended to the Permit2 witness typehash
string constant SWAP_WITNESS_TYPE_STRING = "SwapWitness witness)SwapWitness(address aggregator,bytes32 calldataHash)TokenPermissions(address token,uint256 amount)";

/// @dev EIP-712 typehash for the SwapWitness struct
bytes32 constant SWAP_WITNESS_TYPEHASH = keccak256("SwapWitness(address aggregator,bytes32 calldataHash)");

/// @title SwapCollector
///
/// @notice Collect payments by swapping a payer's input token to the payment's output token via a whitelisted
///         DEX aggregator. Uses Permit2 witness signatures to bind the swap parameters to the payer's authorization.
///
/// @dev The flow is:
///      1. Decode collectorData into (SwapData, signature)
///      2. Validate input token and aggregator whitelists
///      3. Pull input tokens from payer via Permit2 permitWitnessTransferFrom with SwapWitness
///      4. Transfer input tokens to aggregator, execute swap
///      5. Verify output token balance >= required amount
///      6. Send required amount of output tokens to tokenStore
///      7. Refund excess output tokens and unused input tokens to payer
///
/// @author Agentokratia
contract SwapCollector is TokenCollector, ERC6492SignatureHandler, Ownable2Step, Pausable, ReentrancyGuardTransient {
    using SafeERC20 for IERC20;

    /// @notice Swap parameters provided by the caller
    struct SwapData {
        /// @dev Token the payer provides as input for the swap
        address inputToken;
        /// @dev Maximum amount of input tokens the payer authorizes
        uint256 maxInputAmount;
        /// @dev Address of the whitelisted DEX aggregator
        address aggregator;
        /// @dev Calldata to execute on the aggregator
        bytes aggregatorCalldata;
    }

    /// @notice Transfer type for aggregator interaction
    /// @dev Push: safeTransfer tokens to router (Uniswap, payerIsUser=false)
    ///      Pull: approve router to transferFrom (ParaSwap, OpenOcean)
    enum TransferType { Push, Pull }

    /// @inheritdoc TokenCollector
    TokenCollector.CollectorType public constant override collectorType = TokenCollector.CollectorType.Payment;

    /// @notice Permit2 singleton
    ISignatureTransfer public immutable permit2;

    /// @notice Whitelisted input tokens that can be swapped from
    mapping(address token => bool allowed) public whitelistedTokens;

    /// @notice Whitelisted DEX aggregators that can execute swaps
    mapping(address aggregator => bool allowed) public whitelistedAggregators;

    /// @notice Transfer type per aggregator (Push = safeTransfer, Pull = approve+call+revoke)
    mapping(address aggregator => TransferType) public aggregatorTransferType;

    /// @notice Emitted when a swap is executed successfully
    /// @param payer Address that provided the input tokens
    /// @param inputToken Token swapped from
    /// @param outputToken Token swapped to
    /// @param inputAmount Amount of input tokens consumed by the aggregator
    /// @param outputAmount Amount of output tokens received from the swap
    /// @param amountSentToStore Amount of output tokens sent to the token store
    event SwapExecuted(
        address indexed payer,
        address inputToken,
        address outputToken,
        uint256 inputAmount,
        uint256 outputAmount,
        uint256 amountSentToStore
    );

    /// @notice Emitted when a token's whitelist status changes
    /// @param token Token address
    /// @param allowed Whether the token is now allowed
    event TokenWhitelistUpdated(address indexed token, bool allowed);

    /// @notice Emitted when an aggregator's whitelist status changes
    /// @param aggregator Aggregator address
    /// @param allowed Whether the aggregator is now allowed
    event AggregatorWhitelistUpdated(address indexed aggregator, bool allowed);

    /// @notice Emitted when stuck tokens are withdrawn by the owner
    /// @param token Token address
    /// @param to Recipient address
    /// @param amount Amount withdrawn
    event EmergencyWithdraw(address indexed token, address indexed to, uint256 amount);

    /// @notice Input token is not whitelisted
    error TokenNotWhitelisted(address token);

    /// @notice Aggregator is not whitelisted
    error AggregatorNotWhitelisted(address aggregator);

    /// @notice Swap call to aggregator failed
    error SwapFailed(bytes returnData);

    /// @notice Output amount from swap is less than the required amount
    error SlippageExceeded(uint256 outputAmount, uint256 requiredAmount);

    /// @notice Input token address is zero
    error ZeroInputToken();

    /// @notice Aggregator address is zero
    error ZeroAggregator();

    /// @notice Max input amount is zero
    error ZeroMaxInputAmount();

    /// @notice Aggregator calldata is empty
    error EmptyAggregatorCalldata();

    /// @notice Input token cannot be the same as the output token
    error SameInputOutputToken();

    /// @notice Array length mismatch in batch operations
    error ArrayLengthMismatch();

    /// @notice Constructor
    ///
    /// @param authCaptureEscrow_ AuthCaptureEscrow singleton that calls to collect tokens
    /// @param permit2_ Permit2 singleton
    /// @param multicall3_ Public Multicall3 singleton for safe ERC-6492 external calls
    /// @param owner_ Initial owner of the contract
    constructor(address authCaptureEscrow_, address permit2_, address multicall3_, address owner_)
        TokenCollector(authCaptureEscrow_)
        ERC6492SignatureHandler(multicall3_)
        Ownable(owner_)
    {
        permit2 = ISignatureTransfer(permit2_);
    }

    /// @notice Set whitelist status for a single token
    ///
    /// @param token Token address to update
    /// @param allowed Whether the token should be whitelisted
    function whitelistToken(address token, bool allowed) external onlyOwner {
        whitelistedTokens[token] = allowed;
        emit TokenWhitelistUpdated(token, allowed);
    }

    /// @notice Set whitelist status for multiple tokens
    ///
    /// @param tokens Array of token addresses to update
    /// @param allowed Array of whitelist statuses
    function whitelistTokens(address[] calldata tokens, bool[] calldata allowed) external onlyOwner {
        if (tokens.length != allowed.length) revert ArrayLengthMismatch();
        for (uint256 i; i < tokens.length; ++i) {
            whitelistedTokens[tokens[i]] = allowed[i];
            emit TokenWhitelistUpdated(tokens[i], allowed[i]);
        }
    }

    /// @notice Set whitelist status for a single aggregator (defaults to Push transfer type)
    ///
    /// @param aggregator Aggregator address to update
    /// @param allowed Whether the aggregator should be whitelisted
    function whitelistAggregator(address aggregator, bool allowed) external onlyOwner {
        whitelistedAggregators[aggregator] = allowed;
        aggregatorTransferType[aggregator] = TransferType.Push;
        emit AggregatorWhitelistUpdated(aggregator, allowed);
    }

    /// @notice Set whitelist status for a single aggregator with explicit transfer type
    ///
    /// @param aggregator Aggregator address to update
    /// @param allowed Whether the aggregator should be whitelisted
    /// @param transferType Push (safeTransfer to router) or Pull (approve + call + revoke)
    function whitelistAggregator(address aggregator, bool allowed, TransferType transferType) external onlyOwner {
        whitelistedAggregators[aggregator] = allowed;
        aggregatorTransferType[aggregator] = transferType;
        emit AggregatorWhitelistUpdated(aggregator, allowed);
    }

    /// @notice Set whitelist status for multiple aggregators
    ///
    /// @param aggregators Array of aggregator addresses to update
    /// @param allowed Array of whitelist statuses
    function whitelistAggregators(address[] calldata aggregators, bool[] calldata allowed) external onlyOwner {
        if (aggregators.length != allowed.length) revert ArrayLengthMismatch();
        for (uint256 i; i < aggregators.length; ++i) {
            whitelistedAggregators[aggregators[i]] = allowed[i];
            aggregatorTransferType[aggregators[i]] = TransferType.Push;
            emit AggregatorWhitelistUpdated(aggregators[i], allowed[i]);
        }
    }

    /// @notice Pause the contract, preventing new swaps
    function pause() external onlyOwner {
        _pause();
    }

    /// @notice Unpause the contract, allowing swaps again
    function unpause() external onlyOwner {
        _unpause();
    }

    /// @notice Withdraw stuck tokens from this contract in case of emergency
    ///
    /// @param token Token address to withdraw
    /// @param to Recipient address
    /// @param amount Amount to withdraw
    function emergencyWithdraw(address token, address to, uint256 amount) external onlyOwner {
        IERC20(token).safeTransfer(to, amount);
        emit EmergencyWithdraw(token, to, amount);
    }

    /// @inheritdoc TokenCollector
    ///
    /// @dev Decodes collectorData as (SwapData swapData, bytes signature).
    ///      The signature authorizes Permit2 to transfer the input token from the payer,
    ///      with a SwapWitness binding the aggregator and calldata hash.
    function _collectTokens(
        AuthCaptureEscrow.PaymentInfo calldata paymentInfo,
        address tokenStore,
        uint256 amount,
        bytes calldata collectorData
    ) internal override whenNotPaused nonReentrant {
        // Decode swap data and signature
        (SwapData memory swapData, bytes memory signature) = abi.decode(collectorData, (SwapData, bytes));

        // Validate swap inputs
        _validateSwapData(swapData, paymentInfo.token);

        // Record pre-pull balances for refund calculations
        uint256 inputBalanceBeforePull = IERC20(swapData.inputToken).balanceOf(address(this));
        uint256 outputBalanceBeforePull = IERC20(paymentInfo.token).balanceOf(address(this));

        // Handle ERC-6492 signature and pull input tokens from payer
        _pullInputTokens(paymentInfo, swapData, signature);

        // Execute swap and distribute output
        _executeSwapAndDistribute(
            paymentInfo, swapData, tokenStore, amount, inputBalanceBeforePull, outputBalanceBeforePull
        );
    }

    /// @dev Use transient storage reentrancy guard on all chains, not just mainnet.
    ///      Consistent with AuthCaptureEscrow's override.
    function _useTransientReentrancyGuardOnlyOnMainnet() internal view virtual override returns (bool) {
        return false;
    }

    /// @notice Validate swap data inputs and whitelists
    ///
    /// @param swapData Swap parameters to validate
    function _validateSwapData(SwapData memory swapData, address outputToken) internal view {
        if (swapData.inputToken == address(0)) revert ZeroInputToken();
        if (swapData.inputToken == outputToken) revert SameInputOutputToken();
        if (swapData.aggregator == address(0)) revert ZeroAggregator();
        if (swapData.maxInputAmount == 0) revert ZeroMaxInputAmount();
        if (swapData.aggregatorCalldata.length == 0) revert EmptyAggregatorCalldata();
        if (!whitelistedTokens[swapData.inputToken]) revert TokenNotWhitelisted(swapData.inputToken);
        if (!whitelistedAggregators[swapData.aggregator]) revert AggregatorNotWhitelisted(swapData.aggregator);
    }

    /// @notice Pull input tokens from payer via Permit2 witness transfer
    ///
    /// @param paymentInfo Payment info struct
    /// @param swapData Swap parameters
    /// @param signature Payer's Permit2 signature (may be ERC-6492 wrapped)
    function _pullInputTokens(
        AuthCaptureEscrow.PaymentInfo calldata paymentInfo,
        SwapData memory swapData,
        bytes memory signature
    ) internal {
        bytes memory innerSignature = _handleERC6492Signature(signature);

        bytes32 witness =
            keccak256(abi.encode(SWAP_WITNESS_TYPEHASH, swapData.aggregator, keccak256(swapData.aggregatorCalldata)));

        permit2.permitWitnessTransferFrom({
            permit: ISignatureTransfer.PermitTransferFrom({
                permitted: ISignatureTransfer.TokenPermissions({token: swapData.inputToken, amount: swapData.maxInputAmount}),
                nonce: uint256(_getHashPayerAgnostic(paymentInfo)),
                deadline: paymentInfo.preApprovalExpiry
            }),
            transferDetails: ISignatureTransfer.SignatureTransferDetails({
                to: address(this),
                requestedAmount: swapData.maxInputAmount
            }),
            owner: paymentInfo.payer,
            witness: witness,
            witnessTypeString: SWAP_WITNESS_TYPE_STRING,
            signature: innerSignature
        });
    }

    /// @notice Execute the swap on the aggregator and distribute output tokens
    ///
    /// @param paymentInfo Payment info struct
    /// @param swapData Swap parameters
    /// @param tokenStore Address to send required output tokens to
    /// @param amount Required output token amount
    /// @param inputBalanceBeforePull Input token balance before Permit2 pull
    /// @param outputBalanceBeforePull Output token balance before Permit2 pull
    function _executeSwapAndDistribute(
        AuthCaptureEscrow.PaymentInfo calldata paymentInfo,
        SwapData memory swapData,
        address tokenStore,
        uint256 amount,
        uint256 inputBalanceBeforePull,
        uint256 outputBalanceBeforePull
    ) internal {
        // Execute swap via aggregator using the configured transfer type
        bool success;
        bytes memory returnData;

        if (aggregatorTransferType[swapData.aggregator] == TransferType.Push) {
            // Push: transfer tokens to router, router uses own balance (Uniswap, payerIsUser=false)
            IERC20(swapData.inputToken).safeTransfer(swapData.aggregator, swapData.maxInputAmount);
            (success, returnData) = swapData.aggregator.call(swapData.aggregatorCalldata);
            if (!success) revert SwapFailed(returnData);
        } else {
            // Pull: approve router to transferFrom (ParaSwap, OpenOcean)
            IERC20(swapData.inputToken).forceApprove(swapData.aggregator, swapData.maxInputAmount);
            (success, returnData) = swapData.aggregator.call(swapData.aggregatorCalldata);
            IERC20(swapData.inputToken).forceApprove(swapData.aggregator, 0);
            if (!success) revert SwapFailed(returnData);
        }

        // Calculate and verify output
        address outputToken = paymentInfo.token;
        uint256 outputReceived = IERC20(outputToken).balanceOf(address(this)) - outputBalanceBeforePull;
        if (outputReceived < amount) revert SlippageExceeded(outputReceived, amount);

        // Send required amount to token store
        IERC20(outputToken).safeTransfer(tokenStore, amount);

        // Refund excess output tokens to payer
        if (outputReceived > amount) {
            IERC20(outputToken).safeTransfer(paymentInfo.payer, outputReceived - amount);
        }

        // Refund unused input tokens to payer (balance above pre-pull baseline)
        uint256 inputBalanceAfterSwap = IERC20(swapData.inputToken).balanceOf(address(this));
        uint256 unusedInput = inputBalanceAfterSwap - inputBalanceBeforePull;
        if (unusedInput > 0) {
            IERC20(swapData.inputToken).safeTransfer(paymentInfo.payer, unusedInput);
        }

        emit SwapExecuted(
            paymentInfo.payer,
            swapData.inputToken,
            outputToken,
            swapData.maxInputAmount - unusedInput,
            outputReceived,
            amount
        );
    }
}
