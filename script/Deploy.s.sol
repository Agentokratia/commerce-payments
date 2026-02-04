// SPDX-License-Identifier: GPL-3.0
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
 */
import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";

import {AuthCaptureEscrow} from "../src/AuthCaptureEscrow.sol";
import {ERC3009PaymentCollector} from "../src/collectors/ERC3009PaymentCollector.sol";
import {Permit2PaymentCollector} from "../src/collectors/Permit2PaymentCollector.sol";
import {SwapCollector} from "../src/collectors/SwapCollector.sol";
import {MerchantRefundCollector} from "../src/collectors/MerchantRefundCollector.sol";
/**
 * @notice Deploy the Agentokratia Settlement Protocol.
 *
 * Deploys:
 *   1. AuthCaptureEscrow        - Core escrow engine
 *   2. ERC3009PaymentCollector   - USDC gasless signatures
 *   3. Permit2PaymentCollector   - Any ERC-20 same-token payments
 *   4. SwapCollector             - Cross-token payments via DEX swap
 *   5. MerchantRefundCollector   - Merchant-initiated Permit2 refunds
 *
 * Environment variables:
 *   SWAP_COLLECTOR_OWNER - Address that will own the SwapCollector (whitelist, pause, emergency)
 *
 * Deploy:
 *   SWAP_COLLECTOR_OWNER=<addr> forge script Deploy --account dev --sender $SENDER \
 *     --rpc-url $BASE_SEPOLIA_RPC --broadcast -vvvv \
 *     --verify --verifier-url $SEPOLIA_BASESCAN_API --etherscan-api-key $BASESCAN_API_KEY
 */

contract Deploy is Script {
    // Known addresses (same on Base Mainnet & Base Sepolia)
    address constant MULTICALL3 = 0xcA11bde05977b3631167028862bE2a173976CA11;
    address constant PERMIT2 = 0x000000000022D473030F116dDEE9F6B43aC78BA3;

    function run() public {
        address swapCollectorOwner = vm.envAddress("SWAP_COLLECTOR_OWNER");

        vm.startBroadcast();

        // 1. Deploy core escrow
        AuthCaptureEscrow authCaptureEscrow = new AuthCaptureEscrow();

        // 2. Deploy payment collectors
        ERC3009PaymentCollector erc3009Collector = new ERC3009PaymentCollector(address(authCaptureEscrow), MULTICALL3);

        Permit2PaymentCollector permit2Collector =
            new Permit2PaymentCollector(address(authCaptureEscrow), PERMIT2, MULTICALL3);

        SwapCollector swapCollector =
            new SwapCollector(address(authCaptureEscrow), PERMIT2, MULTICALL3, swapCollectorOwner);

        MerchantRefundCollector merchantRefundCollector =
            new MerchantRefundCollector(address(authCaptureEscrow), PERMIT2, MULTICALL3);

        vm.stopBroadcast();

        // Log deployed addresses
        console2.log("Deployed addresses:");
        console2.log("  AuthCaptureEscrow:", address(authCaptureEscrow));
        console2.log("  ERC3009PaymentCollector:", address(erc3009Collector));
        console2.log("  Permit2PaymentCollector:", address(permit2Collector));
        console2.log("  SwapCollector:", address(swapCollector));
        console2.log("  MerchantRefundCollector:", address(merchantRefundCollector));

        // Log known addresses used
        console2.log("\nKnown addresses used:");
        console2.log("  Multicall3:", MULTICALL3);
        console2.log("  Permit2:", PERMIT2);

        // Reminder for post-deployment setup
        console2.log("\nPost-deployment (owner must call on SwapCollector):");
        console2.log("  swapCollector.whitelistToken(tokenAddress, true)");
        console2.log("  swapCollector.whitelistAggregator(aggregatorAddress, true)");
    }
}
