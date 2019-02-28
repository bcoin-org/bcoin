## Getting Started
- [Getting Started](Beginner's-Guide.md)
- [Configuration](Configuration.md)
- [Wallet System](Wallet-System.md)
- [Design](Design.md)
- [Guides](https://bcoin.io/guides.html)

## Running
- [Bcoin CLI](CLI.md)
- [Running in the Browser](https://bcoin.io/guides/browser.html)
- [REST and RPC API](https://bcoin.io/api-docs/index.html#introduction)

## Code Examples

These code examples are designed to demonstrate how to integrate bcoin modules
with minimal configuration.

- [Simple Fullnode](Examples/fullnode.js) - Creates a `FullNode` object and connects to `testnet`.
- [Connect to Peer](Examples/connect-to-peer.js) - Connects to a user-defined peer in `regtest` mode.
- [Connecting to the P2P Network](Examples/connect-to-the-p2p-network.js) - Creates `chain`, `pool`, and `mempool` objects for both main and testnet networks.
- [Creating a Blockchain and Mempool](Examples/create-a-blockchain-and-mempool.js) - Mines a block from the mempool to the chain.
- [Wallet with Dummy TX](Examples/wallet.js) - Adds a "dummy" transaction to the wallet and `tx` event is handled.
- [SPV Sync](Examples/spv-sync-wallet.js) - A transaction matching the SPV node's bloom filter is broadcast by a minimal full node to the SPV node.
- [Plugin Example](Examples/peers-plugin.js) - Demonstrates the `plugin` feature of bcoin's `node` object.
- [Client API Usage](Examples/client-api.js) - Demonstrates usage of the node and wallet API.
- [Create and Sign TX](Examples/create-sign-tx.js) - Demonstrates how to use `mtx` and `keyring` modules to sign a transaction.
- [Get Transaction from Chain](Examples/get-tx-from-chain.js) - Connects to live testnet network and syncs the first 1000 blocks with tx indexing active.
- [Create Watch Only Wallet](Examples/watch-only-wallet.js) - Imports an `xpub` into a new watch-only wallet that can derive addresses.
