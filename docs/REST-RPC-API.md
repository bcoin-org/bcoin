The default bcoin HTTP server listens on the standard RPC port (8332 for main).
It exposes a REST json api, as well as a JSON-RPC api.

## Auth

Auth is accomplished via HTTP Basic Auth, using your node's API key (passed via
`--api-key`).

Example:

``` bash
$ curl http://x:[api-key]@127.0.0.1:8332/
```

## Errors

Errors will be returned with an http status code other than 200, containing a
JSON object in the form:

`{"error": { message: "message" } }`


## Node API

### POST /

Route for JSON-RPC requests, most of which mimic the bitcoind RPC calls
completely.

Example:

- Request Body: `{"method":"getblockchaininfo","params":[]}`
- Response Body: `{"id":...,"result":...}`

### GET /

Get server info. No params.

Example:

- Response Body:

``` json
{
  "version": "1.0.0-alpha",
  "network": "regtest",
  "chain": {
    "height": 177,
    "tip": "18037e4e4906a6c9580356612a42bb4127888354825f4232d811ef7e89af376a",
    "progress": 0.9935725241578355
  },
  "pool": {
    "host": "96.82.67.198",
    "port": 48444,
    "agent": "/bcoin:1.0.0-alpha/",
    "services": "1001",
    "outbound": 1,
    "inbound": 1
  },
  "mempool": {
    "tx": 1,
    "size": 2776
  },
  "time": {
    "uptime": 6,
    "system": 1486696228,
    "adjusted": 1486696228,
    "offset": 0
  },
  "memory": {
    "rss": 63,
    "jsHeap": 24,
    "jsHeapTotal": 34,
    "nativeHeap": 28
  }
}
```

### GET /coin/address/:address

Get coins by address. Returns coins in bcoin coin json format.

*Note: Without `index-address` option, it won't return from chain(only mempool).*

### GET /coin/:hash/:index

Get coin by outpoint (hash and index). Returns coin in bcoin coin json format.

### POST /coin/address

Get coins by addresses. Returns coins in bcoin coin json format.

Example:

- Request Body: `{"addresses":[...]}`
- Response Body: `[...]`

### GET /tx/:hash

Get transaction by TXID from Chain or Mempool. Returns TX in bcoin transaction json format.

*Note: Without `index-tx` option, it won't return from chain.*

### GET /tx/address/:address

Get transactions by address. Returns TXs in bcoin transaction json format.

### POST /tx/address

Get transactions by addresses. Returns TXs in bcoin transaction json format.

Example:

- Request Body: `{"addresses":[...]}`
- Response Body: `[...]`

### GET /block/:block

Get block by hash or height.

### GET /mempool

Get mempool snapshot (array of json txs).

### POST /broadcast

Broadcast a transaction by adding it to the node's mempool. If mempool
verification fails, the node will still forcefully advertise and relay the
transaction for the next 60 seconds.

Example:

- Request Body: `{"tx":"tx-hex"}`
- Response Body: `{"success":true}`

### GET /fee

Estimate smart fee.

Example:

- Request: GET /fee?blocks=1
- Response Body: `{"rate":"0.0005"}`

### POST /reset

Reset blockchain to hash or height. The chain sync will be replayed from this height. Note that this will also rollback any wallets to the specified block.

Example:

- Request: POST /reset?height=100000



## Wallet API

### Wallet Auth

Individual wallets have their own api keys, referred to internally as "tokens"
(a 32 byte hash - calculated as `HASH256(m/44'->ec-private-key|tokenDepth)`).

A wallet is always created with a corresponding token. When using api endpoints
for a specific wallet, the token must be sent back in the query string or json
body.

Examples:

```
POST /wallet/:id/send
{
  token: "64 character hex string",
  ...
}
```

```
GET /wallet/:id/tx/:hash?token=[64 character hex string]
```

### POST /wallet/_admin/rescan

Initiates a blockchain rescan for the walletdb. Wallets will be rolled back to the specified height (transactions above this height will be unconfirmed).

Example:

- Request: POST /wallet/_admin/rescan?height=100000
- Response Body: `{"success":true}`

### POST /wallet/_admin/resend

Rebroadcast all pending transactions in all wallets.

### POST /wallet/_admin/backup

Safely backup the wallet database to specified path (creates a clone of the database).

Example:

- Request: POST /wallet/_admin/backup?path=/home/user/walletdb-backup.ldb
- Response Body: `{"success":true}`

### GET /wallet/_admin/wallets

List all wallet IDs. Returns an array of strings.

### GET /wallet/:id

Get wallet info by ID.

Example:

- Response Body:

``` json
{
  "network": "regtest",
  "wid": 1,
  "id": "primary",
  "initialized": true,
  "watchOnly": false,
  "accountDepth": 1,
  "token": "2d04e217877f15ba920d02c24c6c18f4d39df92f3ae851bec37f0ade063244b2",
  "tokenDepth": 0,
  "state": {
    "tx": 177,
    "coin": 177,
    "unconfirmed": "8150.0",
    "confirmed": "8150.0"
  },
  "master": {
    "encrypted": false
  },
  "account": {
    "name": "default",
    "initialized": true,
    "witness": false,
    "watchOnly": false,
    "type": "pubkeyhash",
    "m": 1,
    "n": 1,
    "accountIndex": 0,
    "receiveDepth": 8,
    "changeDepth": 1,
    "nestedDepth": 0,
    "lookahead": 10,
    "receiveAddress": "mu5Puppq4Es3mibRskMwoGjoZujHCFRwGS",
    "nestedAddress": null,
    "changeAddress": "n3nFYgQR2mrLwC3X66xHNsx4UqhS3rkSnY",
    "accountKey": "tpubDC5u44zLNUVo2gPVdqCbtX644PKccH5VZB3nqUgeCiwKoi6BQZGtr5d6hhougcD6PqjszsbR3xHrQ5k8yTbUt64aSthWuNdGi7zSwfGVuxc",
    "keys": []
  }
}
```

### GET /wallet/:id/master

Get wallet master HD key. This is normally censored in the wallet info route. The provided api key must have _admin_ access.

Example:

- Response Body:

``` json
{
  "encrypted": false,
  "key": {
    "xprivkey": "tprv8ZgxMBicQKsPe7977psQCjBBjWtLDoJVPiiKog42RCoShJLJATYeSkNTzdwfgpkcqwrPYAmRCeudd6kkVWrs2kH5fnTaxrHhi1TfvgxJsZD",
    "mnemonic": {
      "bits": 128,
      "language": "english",
      "entropy": "a560ac7eb5c2ed412a4ba0790f73449d",
      "phrase": "pistol air cabbage high conduct party powder inject jungle knee spell derive",
      "passphrase": ""
    }
  }
}
```

### PUT /wallet/:id

Create a new wallet with a specified ID.

Example:

- Request: PUT /wallet/foo
- Request Body: `{"type":"pubkeyhash"}`
- Response Body:

``` json
{
  "network": "regtest",
  "wid": 2,
  "id": "foo",
  "initialized": true,
  "watchOnly": false,
  "accountDepth": 1,
  "token": "d9de1ddc83bf058d14520a203df6ade0dc92a684aebfac57b667705b4cac3916",
  "tokenDepth": 0,
  "state": {
    "tx": 0,
    "coin": 0,
    "unconfirmed": "0.0",
    "confirmed": "0.0"
  },
  "master": {
    "encrypted": false
  },
  "account": {
    "name": "default",
    "initialized": true,
    "witness": false,
    "watchOnly": false,
    "type": "pubkeyhash",
    "m": 1,
    "n": 1,
    "accountIndex": 0,
    "receiveDepth": 1,
    "changeDepth": 1,
    "nestedDepth": 0,
    "lookahead": 10,
    "receiveAddress": "muYkrSDbD8UhyWBMXxXf99EKWn22YqmwyF",
    "nestedAddress": null,
    "changeAddress": "mwveV7A6svE5EGGSduZmMKTwcbE775NVFt",
    "accountKey": "tpubDDh2XgSds1vBbeVgye88gsGQeCityoywRndtyrXcmvWqCgsFUyUKwzeDv8HiJhu9fC8jRAFMqxr4jj8eRTNTycmMao5wmsAScVf4jSMdPYZ",
    "keys": []
  }
}
```

### GET /wallet/:id/account

List all account names (array indicies map directly to bip44 account indicies).

- Response Body:

``` json
[
  "default"
]
```

### GET /wallet/:id/account/:account

Get account info.

Example:

- Response Body:

``` json
{
  "wid": 1,
  "id": "primary",
  "name": "default",
  "initialized": true,
  "witness": false,
  "watchOnly": false,
  "type": "pubkeyhash",
  "m": 1,
  "n": 1,
  "accountIndex": 0,
  "receiveDepth": 8,
  "changeDepth": 1,
  "nestedDepth": 0,
  "lookahead": 10,
  "receiveAddress": "mu5Puppq4Es3mibRskMwoGjoZujHCFRwGS",
  "nestedAddress": null,
  "changeAddress": "n3nFYgQR2mrLwC3X66xHNsx4UqhS3rkSnY",
  "accountKey": "tpubDC5u44zLNUVo2gPVdqCbtX644PKccH5VZB3nqUgeCiwKoi6BQZGtr5d6hhougcD6PqjszsbR3xHrQ5k8yTbUt64aSthWuNdGi7zSwfGVuxc",
  "keys": []
}
```

### PUT /wallet/:id/account/:name

Create account with specified account name.

Example:

- Request: PUT /wallet/foo/account/my-account

- Response Body:

``` json
{
  "wid": 1,
  "id": "primary",
  "name": "menace",
  "initialized": true,
  "witness": false,
  "watchOnly": false,
  "type": "pubkeyhash",
  "m": 1,
  "n": 1,
  "accountIndex": 1,
  "receiveDepth": 1,
  "changeDepth": 1,
  "nestedDepth": 0,
  "lookahead": 10,
  "receiveAddress": "mg7b3H3ZCHx3fwvUf8gaRHwcgsL7WdJQXv",
  "nestedAddress": null,
  "changeAddress": "mkYtQFpxDcqutMJtyzKNFPnn97zhft56wH",
  "accountKey": "tpubDC5u44zLNUVo55dtQsJRsbQgeNfrp8ctxVEdDqDQtR7ES9XG5h1SGhkv2HCuKA2RZysaFzkuy5bgxF9egvG5BJgapWwbYMU4BJ1SeSj916G",
  "keys": []
}
```

### POST /wallet/:id/passphrase

Change wallet passphrase. Encrypt if unencrypted.

Example:

- Request Body: `{"old":"hunter2","passphrase":"hunter3"}`
- Response Body: `{"success":true}`

### POST /wallet/:id/unlock

Derive the AES key from passphrase and hold it in memory for a specified number
of seconds. __Note:__ During this time, account creation and signing of
transactions will _not_ require a passphrase.

Example:

- Request Body: `{"timeout":60,"passphrase":"hunter3"}`
- Response Body: `{"success":true}`

### POST /wallet/:id/lock

If `unlock` was called, zero the derived AES key and revert to normal behavior.

### POST /wallet/:id/import

Import a standard WIF key. Note that imported keys do not exist anywhere in the
wallet's HD tree. They can be associated with accounts but will _not_ be
properly backed up with only the mnemonic.

A rescan will be required to see any transaction history associated with the
key.

### POST /wallet/:id/retoken

Derive a new wallet token, required for access of this particular wallet.

__Note__: if you happen to lose the returned token, you _will not_ be able to
access the wallet.

Example:

- Response Body:

``` json
{
  "token": "2d04e217877f15ba920d02c24c6c18f4d39df92f3ae851bec37f0ade063244b2"
}
```

### POST /wallet/:id/send

Create, sign, and send a transaction.

Example:

- Request Body:

``` json
{
  "rate": "0.00020",
  "outputs": [{
    "value": "5.0",
    "address": "mu5Puppq4Es3mibRskMwoGjoZujHCFRwGS"
  }]
}
```

- Response Body:

``` json
{
  "wid": 1,
  "id": "primary",
  "hash": "0de09025e68b78e13f5543f46a9516fa37fcc06409bf03eda0e85ed34018f822",
  "height": -1,
  "block": null,
  "time": 0,
  "mtime": 1486685530,
  "date": "2017-02-10T00:12:10Z",
  "index": -1,
  "size": 226,
  "virtualSize": 226,
  "fee": "0.0000454",
  "rate": "0.00020088",
  "confirmations": 0,
  "inputs": [
    {
      "value": "50.0",
      "address": "n4UANJbj2ZWy1kgt9g45XFGp57FQvqR8ZJ",
      "path": {
        "name": "default",
        "account": 0,
        "change": false,
        "derivation": "m/0'/0/0"
      }
    }
  ],
  "outputs": [
    {
      "value": "5.0",
      "address": "mu5Puppq4Es3mibRskMwoGjoZujHCFRwGS",
      "path": {
        "name": "default",
        "account": 0,
        "change": false,
        "derivation": "m/0'/0/7"
      }
    },
    {
      "value": "44.9999546",
      "address": "n3nFYgQR2mrLwC3X66xHNsx4UqhS3rkSnY",
      "path": {
        "name": "default",
        "account": 0,
        "change": true,
        "derivation": "m/0'/1/0"
      }
    }
  ],
  "tx": "0100000001c5b23b4348b7fa801f498465e06f9e80cf2f61eead23028de14b67fa78df3716000000006b483045022100d3d4d945cdd85f0ed561ae8da549cb083ab37d82fcff5b9023f0cce608f1dffe02206fc1fd866575061dcfa3d12f691c0a2f03041bdb75a36cd72098be096ff62a810121021b018b19426faa59fdda7f57e68c42d925752454d9ea0d6feed8ac186074a4bcffffffff020065cd1d000000001976a91494bc546a84c481fbd30d34cfeeb58fd20d8a59bc88ac447b380c010000001976a914f4376876aa04f36fc71a2618878986504e40ef9c88ac00000000"
}
```

### POST /wallet/:id/create

Create and template a transaction (useful for multisig).
Do not broadcast or add to wallet.

- Request Body:

``` json
{
  "outputs": [{
    "value": "5.0",
    "address": "mu5Puppq4Es3mibRskMwoGjoZujHCFRwGS"
  }]
}
```

- Response Body:

``` json
{
  "hash": "0799a1d3ebfd108d2578a60e1b685350d42e1ef4d5cd326f99b8bf794c81ed17",
  "witnessHash": "0799a1d3ebfd108d2578a60e1b685350d42e1ef4d5cd326f99b8bf794c81ed17",
  "fee": "0.0000454",
  "rate": "0.00020088",
  "mtime": 1486686322,
  "version": 1,
  "flag": 1,
  "inputs": [
    {
      "prevout": {
        "hash": "6dd8dfa9b425a4126061a1032bc6ff6e208b75ee09d0aac089d105dcf972465a",
        "index": 0
      },
      "script": "483045022100e7f1d57e47cd8a28b7c27e015b291f3fd43a6eb0c051a4b65d8697b5133c29f5022020cada0f62a32aecd473f606780b2aef3fd9cbd44cfd5e9e3d9fe6eee32912df012102272dae7ff2302597cb785fd95529da6c07e32946e65ead419291258aa7b17871",
      "witness": "00",
      "sequence": 4294967295,
      "coin": {
        "version": 1,
        "height": 2,
        "value": "50.0",
        "script": "76a9149621fb4fc6e2e48538f56928f79bef968bf17ac888ac",
        "address": "muCnMvAoUFZXzuao4oy3vQJFcUntax53wE",
        "coinbase": true
      }
    }
  ],
  "outputs": [
    {
      "value": "5.0",
      "script": "76a91494bc546a84c481fbd30d34cfeeb58fd20d8a59bc88ac",
      "address": "mu5Puppq4Es3mibRskMwoGjoZujHCFRwGS"
    },
    {
      "value": "44.9999546",
      "script": "76a91458e0ea4c9722e7d079ebadb75cb3d8c16dafae7188ac",
      "address": "mocuCKUU6oS6n1yyx81Au71An252SUYwDW"
    }
  ],
  "locktime": 0
}
```

### POST /wallet/:id/sign

Sign a templated transaction (useful for multisig).

### POST /wallet/:id/zap

Remove all pending transactions older than a specified age. Returns array of txids.

Example:

- Request: POST /wallet/primary/zap?age=3600
- Response Body: `[...]`

### DEL /wallet/:id/tx/:hash

Remove a pending transaction.

### GET /wallet/:id/block

List all block heights which contain any wallet txs.

Example:

- Response Body: `[1,2,3]`

### GET /wallet/:id/block/:height

Get block info by height. Contains a list of all wallet txs included in the
block.

Example:

- Request: GET /wallet/primary/block/3
- Response Body:

``` json
{
  "hash": "39864ce2f29635638bbdc3e943b3a182040fdceb6679fa3dabc8c827e05ff6a7",
  "height": 3,
  "time": 1485471341,
  "hashes": [
    "dd1a110edcdcbb3110a1cbe0a545e4b0a7813ffa5e77df691478205191dad66f"
  ]
}
```

### PUT /wallet/:id/shared-key

Add a shared xpubkey to wallet. Must be a `multisig` wallet.

Example:

- Request Body: `{"accountKey":"tpubDC5u44zLNUVo55dtQsJRsbQgeNfrp8ctxVEdDqDQtR7ES9XG5h1SGhkv2HCuKA2RZysaFzkuy5bgxF9egvG5BJgapWwbYMU4BJ1SeSj916G"}`
- Response Body: `{"success":true}`

### DEL /wallet/:id/shared-key

Remove shared xpubkey from wallet if present.

### GET /wallet/:id/key/:address

Get wallet key by address.

### GET /wallet/:id/wif/:address

Get wallet private key (WIF format) by address.

Example:

- Request: GET /wallet/primary/wif/mwX8J1CDGUqeQcJPnjNBG4s97vhQsJG7Eq
- Response Body: `"cQpRMiBcqiyjFratU2ugGEWCmGM8ctb15vhFWd74j3t4m8EzriG2"`

### POST /wallet/:id/address

Derive new receiving address for account.

Example:

- Response Body:

``` json
{
  "network": "regtest",
  "wid": 1,
  "id": "primary",
  "name": "default",
  "account": 0,
  "branch": 0,
  "index": 9,
  "witness": false,
  "nested": false,
  "publicKey": "02801d9457837ed50e9538ee1806b6598e12a3c259fdc9258bbd32934f22cb1f80",
  "script": null,
  "program": null,
  "type": "pubkeyhash",
  "address": "mwX8J1CDGUqeQcJPnjNBG4s97vhQsJG7Eq"
}
```

### POST /wallet/:id/change

Derive new change address for account.

### POST /wallet/:id/nested

Derive new nested p2sh receiving address for account.

### GET /wallet/:id/balance

Get wallet or account balance.

Example:

- Response Body:

``` json
{
  "wid": 1,
  "id": "primary",
  "account": -1,
  "unconfirmed": "8149.9999546",
  "confirmed": "8150.0"
}
```

### GET /wallet/:id/coin

List all wallet coins available.

### GET /wallet/:id/locked

Get all locked outpoints.

Example:

- Response Body:

``` json
[{"hash":"dd1a110edcdcbb3110a1cbe0a545e4b0a7813ffa5e77df691478205191dad66f","index":0}]
```

### PUT /wallet/:id/locked/:hash/:index

Lock outpoints.

### DEL /wallet/:id/locked/:hash/:index

Unlock outpoints.

### GET /wallet/:id/coin/:hash/:index

Get wallet coins.

Example

- Response Body:

``` json
[
  {
    "version": 1,
    "height": -1,
    "value": "44.9999546",
    "script": "76a914f4376876aa04f36fc71a2618878986504e40ef9c88ac",
    "address": "n3nFYgQR2mrLwC3X66xHNsx4UqhS3rkSnY",
    "coinbase": false,
    "hash": "0de09025e68b78e13f5543f46a9516fa37fcc06409bf03eda0e85ed34018f822",
    "index": 1
  }
]
```

### GET /wallet/:id/tx/history

Get wallet TX history. Returns array of tx details.

### GET /wallet/:id/tx/unconfirmed

Get pending wallet transactions. Returns array of tx details.

### GET /wallet/:id/tx/range

Get range of wallet transactions by timestamp. Returns array of tx details.

Example:

- Request: GET /wallet/primary/tx/range?start=1486695017&end=1486695359
- Response Body: `[{tx-details}]`

### GET /wallet/:id/tx/last

Get last N wallet transactions.

### GET /wallet/:id/tx/:hash

Get wallet transaction details.

### POST /wallet/:id/resend

Rebroadcast all pending wallet transactions.



## Wallet Events

Wallet events use the socket.io protocol.

Socket IO implementations:

- JS: https://github.com/socketio/socket.io-client
- Python: https://github.com/miguelgrinberg/python-socketio
- Go: https://github.com/googollee/go-socket.io
- C++: https://github.com/socketio/socket.io-client-cpp

### Wallet Socket Auth

Authentication with the API server must be completed before any other events
will be accepted.

Note that even if the server API key is disabled on the test server, the
`auth` event must still be sent to complete the handshake.

`emit('auth', 'server-api-key')`

The server will respond with a socket.io ACK packet once auth is completed.

### Listening on a wallet

After creating a websocket and authing with the server, you must send a `wallet
join` event to listen for events on a wallet.

`emit('wallet join', 'wallet-id', 'wallet-token')`

### Unlistening on a wallet

`emit('wallet leave', 'wallet-id')`

### Wallet Events

#### `version`

Emitted on connection.

Returns version. Object in the form:
`[{ version: 'v1.0.0-alpha', agent: '/bcoin:v1.0.0-alpha/', network: 'main' }]`.

#### `wallet tx`

Received on transaction.

Example:

``` json
{
  "wid": 1,
  "id": "primary",
  "hash": "0de09025e68b78e13f5543f46a9516fa37fcc06409bf03eda0e85ed34018f822",
  "height": -1,
  "block": null,
  "time": 0,
  "mtime": 1486685530,
  "date": "2017-02-10T00:12:10Z",
  "index": -1,
  "size": 226,
  "virtualSize": 226,
  "fee": "0.0000454",
  "rate": "0.00020088",
  "confirmations": 0,
  "inputs": [
    {
      "value": "50.0",
      "address": "n4UANJbj2ZWy1kgt9g45XFGp57FQvqR8ZJ",
      "path": {
        "name": "default",
        "account": 0,
        "change": false,
        "derivation": "m/0'/0/0"
      }
    }
  ],
  "outputs": [
    {
      "value": "5.0",
      "address": "mu5Puppq4Es3mibRskMwoGjoZujHCFRwGS",
      "path": {
        "name": "default",
        "account": 0,
        "change": false,
        "derivation": "m/0'/0/7"
      }
    },
    {
      "value": "44.9999546",
      "address": "n3nFYgQR2mrLwC3X66xHNsx4UqhS3rkSnY",
      "path": {
        "name": "default",
        "account": 0,
        "change": true,
        "derivation": "m/0'/1/0"
      }
    }
  ],
  "tx": "0100000001c5b23b4348b7fa801f498465e06f9e80cf2f61eead23028de14b67fa78df3716000000006b483045022100d3d4d945cdd85f0ed561ae8da549cb083ab37d82fcff5b9023f0cce608f1dffe02206fc1fd866575061dcfa3d12f691c0a2f03041bdb75a36cd72098be096ff62a810121021b018b19426faa59fdda7f57e68c42d925752454d9ea0d6feed8ac186074a4bcffffffff020065cd1d000000001976a91494bc546a84c481fbd30d34cfeeb58fd20d8a59bc88ac447b380c010000001976a914f4376876aa04f36fc71a2618878986504e40ef9c88ac00000000"
}
```

#### `wallet conflict`

Received on double spend.

Returns tx details of removed double spender.

#### `wallet confirmed`

Received when a transaction is confirmed.

Returns tx details.

#### `wallet unconfirmed`

Received if a transaction was changed from
confirmed->unconfirmed as the result of a reorg.

Returns tx details.

#### `wallet balance`

Received on balance update. Only emitted for
entire wallet balance (not individual accounts).

Example:

``` json
{
  "wid": 1,
  "id": "primary",
  "unconfirmed": "8149.9999546",
  "confirmed": "8150.0"
}
```

#### `wallet address`

Received when a new address is derived.

Example:

``` json
{
  "network": "regtest",
  "wid": 1,
  "id": "primary",
  "name": "default",
  "account": 0,
  "branch": 0,
  "index": 9,
  "witness": false,
  "nested": false,
  "publicKey": "02801d9457837ed50e9538ee1806b6598e12a3c259fdc9258bbd32934f22cb1f80",
  "script": null,
  "program": null,
  "type": "pubkeyhash",
  "address": "mwX8J1CDGUqeQcJPnjNBG4s97vhQsJG7Eq"
}
```
