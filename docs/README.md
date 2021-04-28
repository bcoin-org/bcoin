# Documentation

## Table of contents

- [Getting started](getting-started.md)
- [Configuration](configuration.md)
- [Wallet system](wallet-system.md)
- [Design](design.md)
- [Node and wallet CLI](cli.md)

## External links

- [Guides](https://bcoin.io/guides.html)
- [Running in the browser](https://bcoin.io/guides/browser.html)
- [Node and wallet REST and RPC API](https://bcoin.io/api-docs/index.html)

## Library examples

These code examples are designed to demonstrate how to integrate bcoin modules
with minimal configuration.

- [Simple fullnode](examples/fullnode.js) - Creates a `FullNode` object and
  connects to `testnet`.
- [Connect to peer](examples/connect-to-peer.js) - Connects to a user-defined
  peer in `regtest` mode.
- [Connecting to the P2P network](examples/connect-to-the-p2p-network.js) -
  Creates `chain`, `pool`, and `mempool` objects for both main and
  testnet networks.
- [Creating a blockchain and mempool](examples/create-a-blockchain-and-mempool.js) -
  Mines a block from the mempool to the chain.
- [Wallet with dummy TX](examples/wallet.js) - Adds a "dummy" transaction to
  the wallet and `tx` event is handled.
- [SPV sync](examples/spv-sync-wallet.js) - A transaction matching the SPV
  node's bloom filter is broadcast by a minimal full node to the SPV node.
- [Plugin example](examples/peers-plugin.js) - Demonstrates the `plugin`
  feature of bcoin's `node` object.
- [Client API usage](examples/client-api.js) - Demonstrates usage of the node
  and wallet API.
- [Create and sign TX](examples/create-sign-tx.js) - Demonstrates how to use
  `mtx` and `keyring` modules to sign a transaction.
- [Get transaction from chain](examples/get-tx-from-chain.js) - Connects to
  live testnet network and syncs the first 1000 blocks with tx indexing active.
- [Create watch only wallet](examples/watch-only-wallet.js) - Imports an `xpub`
  into a new watch-only wallet that can derive addresses.
