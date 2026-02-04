# Fork Changes from Commerce Payments Protocol

This repository is a fork of [Commerce Payments Protocol](https://github.com/base/commerce-payments) by Coinbase. Below is a summary of all changes made by Agentokratia.

## AuthCaptureEscrow

**Unchanged from upstream.** The core escrow contract (`src/AuthCaptureEscrow.sol`) is identical to the Base version. Agentokratia uses the upstream `charge()` function for atomic one-step payments with `feeBps=0` and `feeReceiver=0x0`. The authorize/capture flow exists in the contract but is not used by the settlement server.

## New Contracts

### SwapCollector (`src/collectors/SwapCollector.sol`)

Cross-token payment collector. Payers can pay with any whitelisted token (WETH, DAI, etc.) and the collector swaps it to the payment's output token via a whitelisted DEX aggregator.

- Permit2 witness signatures (`SwapWitness`) bind the aggregator address and calldata hash to the payer's authorization, preventing swap parameter tampering.
- Owner-managed whitelists for input tokens and DEX aggregators.
- Transfers input tokens directly to the aggregator (e.g. Uniswap UniversalRouter with `payerIsUser=false`), executes the swap, verifies output meets the required amount.
- Refunds excess output tokens and unused input tokens to the payer.
- Pausable with reentrancy protection.

### MerchantRefundCollector (`src/collectors/MerchantRefundCollector.sol`)

Merchant-initiated refund collector. Replaces upstream's `OperatorRefundCollector` with key differences:

- `collectorType = Refund` (not Payment).
- Permit2 signature owner is `paymentInfo.receiver` (merchant), not payer.
- Merchant-chosen nonce allows multiple partial refunds per payment.
- `collectorData = abi.encode(uint256 nonce, uint256 deadline, bytes signature)`.

### ERC6492SignatureHandler (`src/collectors/ERC6492SignatureHandler.sol`)

Handles [ERC-6492](https://eips.ethereum.org/EIPS/eip-6492) wrapped signatures for smart contract wallets that haven't been deployed yet. Integrated into `Permit2PaymentCollector`, `SwapCollector`, and `MerchantRefundCollector`.

Uses Multicall3 for safe external calls during signature unwrapping.

## Collector Base Changes

### TokenCollector (`src/collectors/TokenCollector.sol`)

- Added `_getHashPayerAgnostic()` helper for payer-agnostic nonce derivation, used by Permit2-based collectors.
- Nonce is derived from `keccak256(chainId, escrowAddress, paymentInfoHash)` rather than payer-specific values.

### Permit2PaymentCollector (`src/collectors/Permit2PaymentCollector.sol`)

- Integrated ERC-6492 signature handling.
- Uses payer-agnostic nonce from `_getHashPayerAgnostic()`.

### ERC3009PaymentCollector (`src/collectors/ERC3009PaymentCollector.sol`)

- Integrated ERC-6492 signature handling.

## TokenStore Changes

- Per-operator liquidity segmentation using CREATE2 clones. Each operator gets an isolated `TokenStore` instance, preventing cross-operator fund mixing.

## Deployment

The deploy script (`script/Deploy.s.sol`) deploys 5 contracts (originally 3):

| # | Contract | Status |
|---|----------|--------|
| 1 | AuthCaptureEscrow | Upstream (unmodified) |
| 2 | ERC3009PaymentCollector | Modified |
| 3 | Permit2PaymentCollector | Modified |
| 4 | SwapCollector | New |
| 5 | MerchantRefundCollector | New (replaces OperatorRefundCollector) |

## Dependencies

- **Permit2** (Uniswap) for signature-based token transfers
- **Solady** for gas-optimized `ReentrancyGuardTransient` and `LibClone`
- **OpenZeppelin** for `SafeERC20`, `Ownable2Step`, `Pausable`

## Security

The original protocol was audited by Spearbit and Coinbase Protocol Security. Agentokratia's additions (SwapCollector, MerchantRefundCollector, ERC-6492 handler) follow the same patterns and conventions. Audit reports for the original protocol are in `audits/`.
