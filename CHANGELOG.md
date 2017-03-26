# Bcoin Release Notes & Changelog

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
