# Getting started

## Introduction

Bcoin is an alternative implementation of the Bitcoin protocol, written in
JavaScript and C/C++ for Node.js. It is a full node which can be used for full
blockchain validation and is aware of all known consensus rules.

## Requirements

- Linux, macOS, or Windows (\*)
- node.js >=v10.0.0
- gpk >= v2 or npm >= v6
- python2 or python3 (for node-gyp)
- gcc/g++ (for leveldb/bdb and secp256k1/bcrypto)
- git

(\*): Note that Bcoin works best with unix-like OSes, and has not yet been
thoroughly tested on Windows. The BSDs and Solaris have also not been tested
yet, but should work in theory.

## Build & install

Bcoin is meant to be installed via Git for security purposes, as there are
security issues when installing via npm. To support signature verification,
[`gpk`][gpk] can be used to replace usage of `npm`. All tagged commits for
a release should be signed by [release maintainers](#maintainers). Signed
copies and source of Node.js are available from [nodejs.org][nodejs],
or from your respective OS's package repositories.

You can add the necessary public keys using `gpg`:
```
gpg --recv-keys "<fingerprint>"
```

### Installing via Git

``` bash
$ git clone https://github.com/bcoin-org/bcoin
$ cd bcoin
```

To verify and checkout a specific release:
```
$ git tag
$ git tag -v <version>
$ git checkout <version>
```

You can also verify signatures using:
```
$ git log --show-signature
```

Build and install globally with `npm`:
```
$ npm rebuild
$ npm install --global
```

Or with [`gpk`][gpk]:

```
$ gpk rebuild
$ gpk install --global
```

Note: If you're updating a repository it is necessary to rebuild
again if any dependencies with native addons have been updated.

### Installing via GPK

To support signature verification, you can use [`gpk`][gpk] to replace the
use of `npm`.

To install `bcoin` globally and to your path:
```
$ gpk install --global https://github.com/bcoin-org/bcoin
```

To install `bcoin` as a dependency, you can create a new
`package.json` with:
```
$ gpk init
```

And then add `bcoin` with:
```
$ gpk install https://github.com/bcoin-org/bcoin
```
The latest tagged version will be added to `package.json` and bcoin
will be installed.

See [GPK documentation][gpk] for further details on usage.

### Installing on Debian/Ubuntu

Install the necessary dependencies in addition to Node.js:
```
apt-get install build-essential python
```

### Installing via Docker

Check [bcoin-docker](https://github.com/bcoin-org/bcoin-docker)

### Installing on Windows

When installing [Node.js via the Windows Installer][nodejs-download],
ensure that the additional build tools are installed during the process,
it will install Python and other build tools.

Also install [Git][git-download] that will include the command `git`
as well as `gpg` via the Git bash shell.

## Use as a dependency

It is recommended to specify bcoin as a git dependency with semantic
versioning and include a mirror in the git tree for integrity and
availability. For example, here is an example `package.json`:

```json
{
  "dependencies": {
    "bcoin": "git+https://github.com/bcoin-org/bcoin.git#semver:~2.0.0"
  }
}
```

While git tags are signed, `npm` will not check the signature
of the git tag. You can use [`gpk`][gpk] instead.

## Starting up your first bcoin node

If bcoin is installed globally, `$ bcoin` should be in your PATH. If not,
the bcoin bootstrap script resides in `/path/to/bcoin/bin/bcoin`.

``` bash
$ bcoin
```

Will run a bcoin node as the foreground process, displaying all debug logs.

To run as a daemon:

``` bash
$ bcoin --daemon
```

This will start up a full node, complete with: a blockchain, mempool, miner,
p2p server, wallet server, and an HTTP REST+RPC server.

All logs will be written to `~/.bcoin/debug.log` by default.

By default, the http server will only listen on `127.0.0.1:8332`. No auth
will be required if an API key was not passed in. If you listen on any other
host, auth will be required and an API key will be auto-generated if one was
not passed in.

## Listening externally

To listen publicly on the HTTP server, `--http-host=0.0.0.0` (ipv4) or
`--http-host=::` (ipv4 and ipv6) can be passed. Additionally this:
`--http-port=1337` can set the port.

To advertise your node on the P2P network `--public-host=[your-public-ip]`
and `--public-port=[your-public-port]` may be passed.

## Using an API Key

If listening publicly on the HTTP server, an API key is required. One will
be randomly generated if no key was chosen, but not explicitly reported to
the user. An API key can be chosen with the `--api-key` option.

Example:

``` bash
$ bcoin --http-host=0.0.0.0 --api-key hunter2 --daemon
```

API keys are used with HTTP Basic Auth:

``` bash
$ curl http://x:hunter2@localhost:8332/
```

If bcoin is installed globally, both `bcoin-cli` and `bwallet-cli` should be
on your path.

``` bash
$ bcoin-cli info --api-key hunter2
$ bcoin-cli rpc getblockchaininfo --api-key hunter2
$ bwallet-cli balance
```

## Using Tor/SOCKS

Bcoin has native support for SOCKS proxies, and will accept a `--proxy` option
in the format of `--proxy=[user]:[pass]@host:port`.

Passing the `--onion` option tells bcoin that the SOCKS proxy is a Tor socks
proxy, and will enable Tor resolution for DNS lookups, as well as try to
connect to `.onion` addresses found on the P2P network.

``` bash
$ bcoin --proxy joe:hunter2@127.0.0.1:9050 --onion
```

### Running bcoin as a Tor hidden service

Your hidden service must first be configured with `tor`. Once you have the
`.onion` address, it can be passed into `--public-host` in the form
of `--public-host foo.onion`.

Note: Use of both `--proxy` and a hidden service at the same time is
currently not yet supported.

## Target nodes

It's often desirable to run behind several trusted bitcoin nodes. To select
permanent nodes to connect to, the `--nodes` option is available:

``` bash
$ bcoin --nodes foo.example.com:8333,1.2.3.4:8333,5.6.7.8:8333
```

If chosen, bcoin will _always_ try to connect to these nodes as outbound
peers. They are top priority and whitelisted (not susceptible to permanent
bans, only disconnections).

To _only_ connect to these nodes, use `--only`

``` bash
$ bcoin --only foo.example.com,1.2.3.4,5.6.7.8
```

## Disabling listening

To avoid accepting connections on the P2P network altogether,
`--listen=false` can be passed to bcoin.

### Selfish mode

Bcoin also supports a "selfish" mode. In this mode, bcoin still has full
blockchain and mempool validation, but network services are disabled: it
will not relay transactions or serve blocks to anyone.

``` bash
$ bcoin --selfish --listen=false
```

Note: Selfish mode is not recommended. We encourage you to _help_ the network
by relaying transactions and blocks. At the same time, selfish mode does have
its uses if you do not have the bandwidth to spare, or if you're absolutely
worried about potential DoS attacks.

## Further configuration

See [Configuration][configuration].

## Maintainers

- Christopher Jeffrey (B4B1 F62D BAC0 84E3 33F3 A04A 8962 AB9D E666 6BBD)
- Braydon Fuller (5B7D C58D 90FE C1E9 90A3  10BA F24F 232D 108B 3AD4)
- Matthew Zipkin (E617 73CD 6E01 040E 2F1B D78C E7E2 984B 6289 C93A)

[keybase]: https://keybase.io/chjj#show-public
[configuration]: configuration.md
[nodejs]: https://nodejs.org/
[giturls]: https://docs.npmjs.com/files/package.json.html#git-urls-as-dependencies
[gpk]: https://github.com/braydonf/gpk
[git-download]: https://git-scm.com/downloads
[nodejs-download]: https://nodejs.org/en/download/
