// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.28;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {MockERC20} from "solady/../test/utils/mocks/MockERC20.sol";

/// @title MockDEXAggregator
/// @notice A configurable mock DEX aggregator for testing SwapCollector.
///         Supports both Push (tokens pre-transferred, like Uniswap) and
///         Pull (transferFrom, like ParaSwap) patterns.
contract MockDEXAggregator {
    bool public shouldFail;
    uint256 public fixedOutputAmount;
    bool public useFixedOutput;

    /// @notice Set whether the swap should revert
    function setShouldFail(bool _shouldFail) external {
        shouldFail = _shouldFail;
    }

    /// @notice Set a fixed output amount (overrides rate-based calculation)
    function setOutputAmount(uint256 amount) external {
        fixedOutputAmount = amount;
        useFixedOutput = true;
    }

    /// @notice Clear fixed output amount to use rate-based calculation
    function clearFixedOutput() external {
        useFixedOutput = false;
    }

    /// @notice Simulate a swap: accept inputToken (push or pull), mint outputToken
    /// @param inputToken The input token address
    /// @param outputToken The token to mint to msg.sender
    /// @param inputAmount Amount of input tokens to consume
    /// @param minOutputAmount Minimum output tokens expected (ignored in mock)
    function swap(address inputToken, address outputToken, uint256 inputAmount, uint256 minOutputAmount) external {
        if (shouldFail) revert("MockDEXAggregator: swap failed");

        // Support both Push and Pull patterns:
        // Push: caller already transferred tokens to us (check balance)
        // Pull: caller approved us, we transferFrom
        uint256 balance = IERC20(inputToken).balanceOf(address(this));
        if (balance < inputAmount) {
            // Pull pattern: need to pull remaining tokens
            IERC20(inputToken).transferFrom(msg.sender, address(this), inputAmount - balance);
        } else if (balance > inputAmount) {
            // Push pattern with excess: return unused tokens to caller
            IERC20(inputToken).transfer(msg.sender, balance - inputAmount);
        }

        // Calculate output amount
        uint256 outputAmount;
        if (useFixedOutput) {
            outputAmount = fixedOutputAmount;
        } else {
            // Default 1:1 rate
            outputAmount = inputAmount;
        }

        // Mint output tokens to caller
        MockERC20(outputToken).mint(msg.sender, outputAmount);
    }
}
