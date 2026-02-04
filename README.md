```
    •  •  •
      ╱╲
     ╱  ╲
    ╱ ╱╲ ╲
   ╱_╱  ╲_╲
```

# Agentokratia Settlement Protocol

A permissionless protocol for onchain payments that mimics traditional "authorize and capture" payment flows. Built on top of the [Commerce Payments Protocol](https://github.com/base/commerce-payments) by Coinbase.

## Quick Start

The Agentokratia Settlement Protocol facilitates secure escrow-based payments with flexible authorization and capture patterns. Operators drive payment flows using modular token collectors while the protocol ensures payer and merchant protections.

**[Read the Full Documentation](docs/README.md)**

## Key Features

- **Two-Phase Payments**: Separate authorization and capture for guaranteed merchant payments and management of real-world complexity
- **Flexible Fee Structure**: Configurable fee rates and recipients within predefined ranges
- **Modular Token Collection**: Support for multiple authorization methods (ERC-3009, Permit2, cross-token swaps)
- **Cross-Token Payments**: SwapCollector enables paying with any whitelisted token via DEX aggregator swaps
- **Built-in Protections**: Time-based expiries, amount limits, and reclaim mechanisms
- **Operator Model**: Permissionless operators manage payment flows while remaining trust-minimized

## Deployed Contracts

The protocol deploys 4 contracts:

| Contract | Purpose |
|----------|---------|
| **AuthCaptureEscrow** | Core escrow engine managing the full payment lifecycle |
| **ERC3009PaymentCollector** | USDC gasless payments via `receiveWithAuthorization` signatures |
| **Permit2PaymentCollector** | Same-token payments for any ERC-20 via Permit2 signatures |
| **SwapCollector** | Cross-token payments via whitelisted DEX aggregator swaps |

## Documentation

- **[Protocol Overview](docs/README.md)** - Architecture, components, and payment lifecycle
- **[Security Analysis](docs/Security.md)** - Security features, risk assessment, and mitigation strategies
- **[Token Collectors Guide](docs/TokenCollectors.md)** - Modular payment authorization methods
- **[Fee System](docs/Fees.md)** - Comprehensive fee mechanics and examples
- **Core Operations:**
  - [Authorize](docs/operations/Authorize.md) - Reserve funds for future capture
  - [Capture](docs/operations/Capture.md) - Transfer authorized funds to merchants
  - [Charge](docs/operations/Charge.md) - Immediate authorization and capture
  - [Void](docs/operations/Void.md) - Cancel authorizations (operator)
  - [Reclaim](docs/operations/Reclaim.md) - Recover expired authorizations (payer)
  - [Refund](docs/operations/Refund.md) - Return captured funds to payers

## Development

```bash
# Install dependencies
forge install

# Run tests
forge test

# Deploy
SWAP_COLLECTOR_OWNER=<addr> forge script script/Deploy.s.sol \
  --rpc-url $RPC_URL --broadcast --verify
```

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Security Audits

The underlying Commerce Payments Protocol has been audited by [Spearbit](https://spearbit.com/) and Coinbase Protocol Security.

| Audit | Date | Report |
|--------|---------|---------|
| Coinbase Protocol Security audit 1 | 03/19/2025 | [Report](audits/CommercePaymentsAudit1ProtoSec.pdf) |
| Coinbase Protocol Security audit 2 | 03/26/2025 | [Report](audits/CommercePaymentsAudit2ProtoSec.pdf) |
| Spearbit audit 1 | 04/01/2025 | [Report](audits/Cantina-Report-04-01-2025.pdf) |
| Coinbase Protocol Security audit 3 | 04/15/2025 | [Report](audits/CommercePaymentsAudit3CoinbaseProtoSec.pdf) |
| Spearbit audit 2 | 04/22/2025 | [Report](audits/Cantina-Report-04-22-2025.pdf) |
