# Node and wallet CLI

Bcoin ships with [bclient](https://github.com/bcoin-org/bclient) as its
default client to the [API](https://bcoin.io/api-docs) for command
line access.

## Configuration

Using environment variables:
```bash
$ export BCOIN_API_KEY=hunter2
$ export BCOIN_NETWORK=testnet
$ bcoin --daemon
$ bcoin-cli info
```

With command-line arguments:

```bash
$ bcoin-cli --network=testnet --api-key=hunter2 info
```

You can also use `~/.bcoin/bcoin.conf` for configuration options,
see [Configuration](configuration.md) for the full details.

## Examples

Common node commands:

```bash
# View the genesis block
$ bcoin-cli block 0

# View the mempool
$ bcoin-cli mempool

# Execute an RPC command to list network peers
$ bcoin-cli rpc getpeerinfo
```

Common wallet commands:

```bash
# View primary wallet
$ bwallet-cli get

# View transaction history
$ bwallet-cli history

# Send a transaction
$ bwallet-cli send <address> 0.01

# View balance
$ bwallet-cli balance

# Derive new address
$ bwallet-cli address

# Create a new account
$ bwallet-cli account create foo

# Send from account
$ bwallet-cli send <address> 0.01 --account=foo
```

Get more help:

```bash
$ bcoin-cli help
$ bcoin-cli rpc help
$ bwallet-cli help
$ bwallet-cli rpc help
```
