# Bcoin

[![NPM Version][npm-version-img]][npm-version-url]
[![Build Status][travis-status-img]][travis-status-url]
[![Coverage Status][coverage-status-img]][coverage-status-url]

__NOTE__: The latest release of bcoin contains a non-backward compatible change
to the rest API. Please read the [changelog]'s "migrating" section for more
details.

---

**Bcoin** is an alternative implementation of the bitcoin protocol, written in
node.js.

Although still in a beta state, bcoin is well tested and aware of all known
consensus rules. It is currently used in production as the consensus backend
and wallet system for [purse.io][purse].

## Uses

- Full Node
- SPV Node
- Wallet Backend (bip44 derivation)
- Mining Backend (getblocktemplate support)
- Layer 2 Backend (lightning)
- General Purpose Bitcoin Library

Try it in the browser: http://bcoin.io/browser.html

## Install

```
$ git clone git://github.com/bcoin-org/bcoin.git
$ cd bcoin
$ npm install
$ ./bin/bcoin
```

See the [Beginner's Guide][guide] for more in-depth installation instructions.

## Documentation

- API Docs: http://bcoin.io/docs/
- REST Docs: [docs/REST-RPC-API](docs/REST-RPC-API.md)
- Docs: [docs/](docs/README.md)

## Support

Join us on [freenode][freenode] in the [#bcoin][irc] channel.

## Disclaimer

Bcoin does not guarantee you against theft or lost funds due to bugs, mishaps,
or your own incompetence. You and you alone are responsible for securing your
money.

## Contribution and License Agreement

If you contribute code to this project, you are implicitly allowing your code
to be distributed under the MIT license. You are also implicitly verifying that
all code is your original work. `</legalese>`

## License

- Copyright (c) 2014-2015, Fedor Indutny (MIT License).
- Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).

See LICENSE for more info.

[purse]: https://purse.io
[guide]: https://github.com/bcoin-org/bcoin/blob/master/docs/Beginner's-Guide.md
[freenode]: https://freenode.net/
[irc]: irc://irc.freenode.net/bcoin
[changelog]: https://github.com/bcoin-org/bcoin/blob/master/CHANGELOG.md

[npm-version-img]: https://img.shields.io/npm/v/bcoin.svg
[npm-version-url]: https://npmjs.org/package/bcoin
[coverage-status-img]: https://coveralls.io/repos/github/bcoin-org/bcoin/badge.svg?branch=master
[coverage-status-url]: https://coveralls.io/github/bcoin-org/bcoin?branch=master
[travis-status-img]: https://travis-ci.org/bcoin-org/bcoin.svg?branch=master
[travis-status-url]: https://travis-ci.org/bcoin-org/bcoin
