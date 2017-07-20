By default, the mainnet bcoin config file will reside in ~/.bcoin/bcoin.conf.

All bcoin configuration options work in the config file, CLI arguments, and
process environment (with a `BCOIN_` prefix).

## Datadir/Prefix

Bcoin's datadir is determined by the `prefix` option.

Example:

``` bash
$ bcoin --prefix ~/.bcoin_spv --spv
```

Will create a datadir of `~/.bcoin_spv`, containing a chain database, wallet database and log file.

## Common Options

- `config`: Points to a custom config file, not in the prefix directory.
- `network`: Which network's chainparams to use for the node (main, testnet, regtest, or segnet4) (default: main).
- `use-workers`: Whether to use a worker process pool for transaction verification (default: true).
- `max-workers`: Number of worker processes to spawn for transaction verification. By default, the worker pool will be sized based on the number of CPUs/cores in the machine.
- `sigcache-size`: Max number of items in signature cache.

## Node Options

- `prefix`: The data directory (stores databases, logs, and configs) (default=~/.bcoin).
- `db`: Which database backend to use (default=leveldb).
- `max-files`: Max open files for leveldb. Higher generally means more disk page cache benefits, but also more memory usage (default: 64).
- `cache-size`: Size (in MB) of leveldb cache and write buffer (default: 32mb).

## Logger Options

- `log-level`: `error`, `warning`, `info`, `debug`, or `spam` (default: debug).
- `log-console`: `true` or `false` - whether to actually write to stdout/stderr
  if foregrounded (default: true).
- `log-file`: Whether to use a log file (default: true).

## Chain Options

Note that certain chain options affect the format and indexing of the chain database and must be passed in consistently each time.

- `prune`: Prune from the last 288 blocks (default: false).
- `checkpoints`: Use checkpoints and getheaders for the initial sync (default: true).
- `coin-cache`: The size (in MB) of the in-memory UTXO cache. By default, there is no UTXO cache enabled. To get a good number of cache hits per block, the coin cache has to be fairly large (60-100mb recommended at least).
- `index-tx`: Index transactions (enables transaction endpoints in REST api) (default: false).
- `index-address`: Index transactions and utxos by address (default: false).

## Mempool Options

- `mempool-size`: Max mempool size in MB (default: 100).
- `replace-by-fee`: Allow replace-by-fee transactions (default: false).
- `persistent-mempool`: Save mempool to disk and read into memory on boot (default: false).

## Pool Options

- `selfish`: Enable "selfish" mode (no relaying of txes or blocks) (default: false).
- `compact`: Enable compact block relay (default: true).
- `bip37`: Enable serving of bip37 merkleblocks (default: false).
- `bip151`: Enable bip151 peer-to-peer encryption (default: false).
- `listen`: Accept incoming connections (default: true).
- `max-outbound`: Max number of outbound connections (default: 8).
- `max-inbound`: Max number of inbound connections (default: 30).
- `seeds`: Custom list of DNS seeds (comma-separated).
- `host`: Host to listen on (default: 0.0.0.0).
- `port`: Port to listen on (default: 8333).
- `public-host`: Public host to advertise on network.
- `public-port`: Public port to advertise on network.
- `bip150`: Enable bip150 peer auth (default: false).
- `identity-key`: BIP150 identity key (32 byte hex string).
- `auth-peers`: Path to `authorized-peers` file for BIP150.
- `known-peers`: Path to `known-peers` file for BIP150.
- `nodes`: List of target nodes to connect to (comma-separated).

## Miner Options

- `coinbase-flags`: Coinbase flags (default: mined by bcoin).
- `coinbase-address`: List of payout addresses, randomly selected during block creation (comma-separated).
- `max-block-weight`: Max block weight to mine (default: 4000000).
- `reserved-block-weight`: Amount of space reserved for coinbase (default: 4000).
- `reserved-block-sigops`: Amount of sigops reserved for coinbase (default: 400).

## HTTP

- `http-host`: HTTP host to listen on (default: 127.0.0.1).
- `http-port`: HTTP port to listen on (default: 8332).
- `ssl-cert`: Path to SSL cert.
- `ssl-key`: Path to SSL key.
- `service-key`: Service key (used for accessing wallet system only).
- `api-key`: API key (used for accessing all node APIs).
- `wallet-auth`: Enable token auth for wallets (default: false).
- `no-auth`: Disable auth for API server and wallets (default: false).

## Sample Config File

See https://github.com/bcoin-org/bcoin/blob/master/etc/sample.conf.