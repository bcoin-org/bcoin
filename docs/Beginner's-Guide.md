## Introduction

Bcoin is an _alternative_ implementation of the bitcoin protocol, written in node.js. It is a full node which can be used for full blockchain validation and is aware of all known consensus rules.

## Requirements

- Linux, OSX, or Windows (\*) (\*\*)
- node.js >=v5.0.0
- npm >=v4.0.0
- python2 (for node-gyp)
- gcc/g++ (for leveldb and secp256k1)
- git (optional, see below)

(\*): Note that bcoin works best with unix-like OSes, and has not yet been thoroughly tested on windows.

(\*\*): The BSDs and Solaris have also not been tested yet, but should work in theory.

## Build & Install

Bcoin is meant to be installed via npm, but for the security conscious, it may be better to clone from github. All tagged commits for release should be signed by @chjj's [PGP key][keybase] (`B4B1F62DBAC084E333F3A04A8962AB9DE6666BBD`). Signed copies of node.js are available from [nodejs.org][node], or from your respective OS's package repositories.

### Installing via NPM

``` bash
$ npm install -g bcoin --production
```

### Installing via Git

``` bash
$ curl https://keybase.io/chjj/pgp_keys.asc | gpg --import
$ git clone git://github.com/bcoin-org/bcoin.git
$ cd bcoin
$ git tag
...
v1.0.0-alpha # latest version
$ git tag -v v1.0.0-alpha # verify signature
$ git checkout v1.0.0-alpha
$ npm install -g --production
```

### Troubleshooting

If the build fails compilation for `bcoin-native` or `secp256k1-node` __validation will be slow__ (a block verification which should take 1 second on consumer grade hardware may take up to 15 seconds). Bcoin will throw a warning on boot if it detects a build failure. If you run into this issue, please post an issue on the repo.

## Starting up your first bcoin node

If bcoin is installed globally, `$ bcoin` should be in your PATH. If not, the bcoin bootstrap script resides in `/path/to/bcoin/bin/bcoin`.

``` bash
$ bcoin
```

Will run a bcoin node as the foreground process, displaying all debug logs.

To run as a daemon:

``` bash
$ bcoin --daemon
```

This will start up a full node, complete with: a blockchain, mempool, miner, p2p server, wallet server, and an HTTP REST+RPC server.

All logs will be written to `~/.bcoin/debug.log` by default.

By default, the http server will only listen on `127.0.0.1:8332`. No auth will be required if an API key was not passed in. If you listen on any other host, auth will be required and an API key will be auto-generated if one was not passed in.

## Listening Externally

To listen publicly on the HTTP server, `--http-host=0.0.0.0` (ipv4) or `--http-host=::` (ipv4 and ipv6) can be passed. Additionally this: `--http-port=1337` can set the port.

To advertise your node on the P2P network `--public-host=[your-public-ip]` and `--public-port=[your-public-port]` may be passed.

## Using an API Key

If listening publicly on the HTTP server, an API key is required. One will be generated and reported in the logs automatically if no key was chosen. An api key can be chosen with the `--api-key` option.

Example:

``` bash
$ bcoin --http-host=0.0.0.0 --api-key hunter2 --daemon
```

API keys are used with HTTP Basic Auth:

``` bash
$ curl http://x:hunter2@localhost:8332/
```

Bcoin CLI is the prepackaged tool for hitting both the REST and RPC api.

``` bash
$ bcoin cli info --api-key hunter2
$ bcoin rpc getblockchaininfo --api-key hunter2
```

## Using Tor/SOCKS

Bcoin has native support for SOCKS proxies, and will accept a `--proxy` option in the format of `--proxy=[user]:[pass]@host:port`.

Passing the `--onion` option tells bcoin that the SOCKS proxy is a Tor socks proxy, and will enable Tor resolution for DNS lookups, as well as try to connect to `.onion` addresses found on the P2P network.

``` bash
$ bcoin --proxy joe:hunter2@127.0.0.1:9050 --onion
```

### Running bcoin as a tor hidden service

Your hidden service must first be configured with `tor`. Once you have the `.onion` address, it can be passed into `--public-host` in the form of `--public-host foo.onion`.

## Target Nodes

It's often desirable to run behind several trusted bitcoin nodes. To select permanent nodes to connect to, the `--nodes` option is available:

``` bash
$ bcoin --nodes foo.example.com:8333,1.2.3.4:8333,5.6.7.8:8333
```

If chosen, bcoin will _always_ try to connect to these nodes as outbound peers. They are top priority and whitelisted (not susceptible to permanent bans, only disconnections).

To _only_ connect to these nodes. `--max-outbound` could be set to 3:

``` bash
$ bcoin --nodes foo.example.com,1.2.3.4,5.6.7.8 --max-outbound 3
```

## Disabling Listening

To avoid accepting connections on the P2P network altogether, `--listen=false` can be passed to bcoin.

### Selfish Mode

Bcoin also supports a "selfish" mode. In this mode, bcoin still has full blockchain and mempool validation, but network services are disabled: it will not relay transactions or serve blocks to anyone.

``` bash
$ bcoin --selfish --listen=false
```

Note: Selfish mode is not recommended. We encourage you to _help_ the network by relaying transactions and blocks. At the same time, selfish mode does have its uses if you do not have the bandwidth to spare, or if you're absolutely worried about potential DoS attacks.

## Further Configuration

See [Configuration][configuration].

[keybase]: https://keybase.io/chjj#show-public
[node]: https://nodejs.org/dist/v7.5.0/
[configuration]: Configuration.md
