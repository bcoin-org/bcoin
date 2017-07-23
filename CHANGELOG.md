# Bcoin Release Notes & Changelog

## v1.0.0-beta.14

### Notable Changes

- __pkg__ - Ignored `bcoin*` files in npmignore have been removed. This fixes
  the npm install.

## v1.0.0-beta.13

### Notable Changes

- __config__ - Options using megabyte units are now calculated properly again
  (6182df044228f9215938e7d314435f3f2640acca,
  a630d23a97b68f189a85105856fedc4e9e515754,
  7728a0047053d4c368e60426e5fc7cc812d54caf).

- __address__ - Bech32 addresses are now supported
  (6acef06cbc87a3051ba238a2fb640562e718135e). This changes the semantics of
  the `Address` object: to support bech32, `Address.fromBase58` calls should be
  replaced with `Address.fromString`.  Likewise, `addr.toBase58` calls should
  be replaced with `addr.toString`

- __rpc__ - `getblockbyheight` is now exposed via JSON-RPC. It takes the same
  parameters as the `getblock` call, requiring a height instead of block hash
  (12d3ee6f9582afa9a3ba8984c63dcbc27b8db57e).

- __bin__ - `bcoin --version` and `bcoin --help` now exit with appropriate
  messages (f2f94a800e37c5dbdda6920fa6b85fbd485c212a).

- __net__ - The p2p pool now exposes an `--only` option
  (a1d0948f2e528c5d77d6502659fafd064b1e693b).

- __mempool__ - The mempool `indexAddress` option should now work correctly
  (fba9b46d253c19bbf8e662d9d75ab03dc9e20a78).

- __rpc__ - JSON-RPC calls now properly cast booleans a la bitcoin core
  (dd49ee076196d2353783e3044185165dbac4aeb9).

- __rpc__ - Various RPC calls have been improved and updated
  (c78707ed6a71ce46c41c4e43ecb505e78a84b380,
  c1e684dc12d0a86573a905d54d4f81fce921987a,
  5bde338a53117b1bd0fd92df0abc23d95180ab32).

- __rpc__ - Retroactive pruning is now available via the `pruneblockchain` call
  (f0bc6d5925419ba4a8289fa7828efc48ecc152d4).

- __http__ - Getting block by height via the Rest API now works again
  (df4c8cc68c965bd818a5004354d2652751d4a702).

- __net__ - Peers who serve invalid orphans are now punished properly
  (0ceca23cb5a3d724c79c6bf587ede5d473df8486).

- __utils__ - An implementation of GCS filters is now supported
  (b994c278f25408886c3095d0c24123baaf07f78f).

- __http__ - The `witness` option is now properly exposed on the Rest API for
  segwit wallets (f04ad612b216becd35765c6e231f7820c7eee358).

- __deps__ - Node.js >=v7.6.0 is now a required dependency
  (a0bd9680fed07c5eb37c227d160b0868f8adaf31).

- __build__ - The browser build has switched from browserify to webpack
  (19f236f74072d473123d20282d2119f6d9130458).

- __bcoin__ - The codebase has been rewritten to use all ES6 and ES7 features
  supported by node.js
  (aa05bb5df79d9a3af53060a4c0c066226f6e9e4c,
  78d62c73b82e1953999d1cf80c90ed2035d4996e,
  e00472891df5934d8fc3aa63662f852816aa86b0,
  c53f4cf89e46d9de8ab7f65430310567558fe03f,
  8c7279518f5341a2482a79ac98f0574468541edc).

- __workers__ - The worker pool has been refactored to solve the dissonance
  between the browser and node.js (27c60ce76e57af1695d78f912227d93194812c88).

- __net__ - DNS requests should now timeout sooner
  (647b6909c6d527eb82f6d789c88a23b2f8a60126).

- __http__ - Satoshi values are now required for all JSON serialization, as
  opposed to BTC strings which were used in the past
  (2f51fd1c5066f194a5a52383f4dd45497b882706).

- __bin__ - The `--no-wallet` flag is now exposed for nodes who want to run
  without a wallet.

- __chain__ - BIP91 support is now exposed via the `--bip91` option.  The
  `segwit` and `segsignal` rules will be automatically added when calling
  `getblocktemplate`. To enable bip91 on an existing database `--force-flags`
  must be passed. This will force bip91 to be enforced, but will not invalidate
  any previous blocks (`bcoin cli reset [height]` may need to be used).

- __chain__ - BIP148 support is now exposed via the `--bip148` option. This
  likewise must be enabled with `--force-flags` on existing chains. This has
  the same potential "reset" implications as the `--bip91` option.

### Migrating

This release contains a few non-backward-compatible changes.

Bcoin now requires node.js >=7.6.0 due to the use of ES6/7 features, and for
the sake of more stability.

Bcoin's rest API now assumes satoshi values for in all JSON serialization.
__This is a breaking change__ for code that is not aware of it. All code which
hits the rest API must be updated to use only satoshi values as opposed to BTC
strings.

In other words, this:

``` json
{
  "unconfirmed": "1.12",
  "confirmed": "1.12"
}
```

Becomes this:

``` json
{
  "unconfirmed": 112000000,
  "confirmed": 112000000
}
```

## v1.0.0-beta.12

### Notable Changes

- __networks__ - Fixed simnet wpkh prefix.
- __http__ - `wallet join` without wallet auth has been fixed for responses.
  This was causing a hanging issue with the client.

## v1.0.0-beta.11

### Notable Changes

- __networks__ - Simnet params have been fixed.
- __cli__ - Chain reset call has been fixed.

## v1.0.0-beta.10

### Notable Changes

- __wallet/http__ - Create wallet route modified
  (`POST /wallet/:id?` changed to `PUT /wallet/:id`).
- __wallet/http__ - Create account route modified
  (`POST /wallet/:id/account/:account?` changed to
  `PUT /wallet/:id/account/:account`).
- __wallet/http__ - `auth` socket.io event name for wallet auth changed to
  `wallet auth`.
- __config__ - `payout-address` option was changed to `coinbase-address`.
- __node__ - Plugin system is now exposed.
  See https://github.com/bcoin-org/bcoin/pull/156.
- __config__ - The internal API for the config object has been rewritten
  and is now more reusable, particularly by node plugins.
- __http/rpc__ - Both the HTTPBase and RPCBase objects now allow "mounting" by
  other rpc and http servers.
- __wallet__ - The wallet code has been completely removed from the node, and
  now resides entirely within one module. The wallet is exposed only as a
  plugin or a separate server.
- __rpc__ - `prioritisetransaction` is now exposed properly (`deltaFee`s are
  now tracked on mempool entries).
- __rpc__ - Proper `id` and error codes are now implemented.
- __rpc__ - Several `getblocktemplate` improvements have been implemented for
  more accuracy. e.g. `curtime` will now be updated each call.
- __mining__ - The internal miner API has been rewritten, and now mimics
  stratum in a sense.
- __chain__ - Faster verification with checkpoints.
- __net__ - Fixed a potential block stalling issue.
- __net__ - Hardcoded seeds for main added. Makes
  for better shipping with browsers.
- __wsproxy/proxysocket__ - DNS resolution is no longer exposed.
- __logger__ - Log files now trim to 20mb on boot.
- __hostlist__ - A persistent `hosts` file is now written by default.

## v1.0.0-beta.9

### Notable Changes

- __mempool__ - Trimming now removes dependency chains by cumulative fee rate.
- __mempool__ - Cumulative descendant fees are now updated properly when
  removing a transaction.
- __net__ - Preliminary upnp support for adding port mappings.
- __chain/mempool/miner__ - Various atomicity fixes and extra sanity checking.
- __pool/peer__ - Peer height is now tracked and exposed on the RPC as
  `bestheight`.

## v1.0.0-beta.8

### Notable Changes

- __mempool__ - Fixed critical fee estimator bug causing throwing in the
  mempool.

## v1.0.0-beta.7

### Notable Changes

- __http__ - Always display spent coins in tx routes (e.g. `/tx/[txid]`).
- __mempool__ - An on-disk mempool is now exposed via `--persistent-mempool`
  (also makes fee data persistent).
- __chain__ - `chain.add` now takes a `flags` parameter to avoid POW and
  non-contextual checks if necessary.
- __net__ - HostList is now potentially persistent with a `hostLocation` option.
- __net__ - Smarter stall behavior and timeouts.

## v1.0.0-beta.6

### Notable Changes

- __http__ - Better bitcoind compatability for JSON-RPC.

## v1.0.0-beta.5

### Notable Changes

- __miner__ - Better fee rate comparisons.
- __deps__ - Upgrade deps, fix build on arm and windows.

## v1.0.0-beta.4

### Notable Changes

- __miner__ - Optimized TX sorting.
- __rpc__ - Improved getblocktemplate to provide more
  accurate results to bitcoind.

## v1.0.0-beta.3

### Notable Changes

- __miner__ - Improved fee rate sorting.
- __rpc__ - Fix incompatibilities in rpc api (getblocktemplate & submitblock).

## v1.0.0-beta.2

### Notable Changes

- __pool__ - Increase max header chain failures to 500 (prevents the initial
  sync from reverting to getblocks so frequently).

## v1.0.0-beta.1

### Notable Changes

- __wsproxy__: Fixed proof of work handling in websocket proxy (43c491b).
- __chain__: Optimized MTP and network target calculations (1e07d1b).
- __wallet__: Implemented "smart" coin selection (304f0e7e).
- __protocol__: Increased default network fees for main (09c2357).
- __http__: Fix for handling `DELETE` http method (393dd5d).
- __miner__: Improved handling of default reserved size and sigops (f2964e0
  and 7104e4c).

## v1.0.0-beta

### Notable Changes

- Initial tagged release.
