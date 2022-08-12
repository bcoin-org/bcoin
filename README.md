# Bcoin

[![Build Status][circleci-status-img]][circleci-status-url]
[![Coverage Status][coverage-status-img]][coverage-status-url]

**Bcoin** is an alternative implementation of the Bitcoin protocol, written in
JavaScript and C/C++ for Node.js.

Bcoin is well tested and aware of all known consensus rules. It is currently
used in production as the consensus backend and wallet system for
[purse.io][purse].

## Uses

- Full Node
- SPV Node
- Wallet Backend
- Mining Backend (getblocktemplate support)
- Layer 2 Backend (lightning)
- General Purpose Bitcoin Library

## Install

```
$ git clone https://github.com/bcoin-org/bcoin
$ cd bcoin
$ npm rebuild
$ ./bin/bcoin
```

See the [Getting started][guide] guide for more in-depth installation
instructions, including verifying releases. If you're upgrading, see the
latest changes via the [Changelog][changelog].

## Documentation

- General docs: [docs/](docs/README.md)
- Wallet and node API docs: https://bcoin.io/api-docs/
- Library API docs: https://bcoin.io/docs/

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
[guide]: docs/getting-started.md
[freenode]: https://freenode.net/
[irc]: irc://irc.freenode.net/bcoin
[changelog]: CHANGELOG.md

[coverage-status-img]: https://codecov.io/gh/bcoin-org/bcoin/badge.svg?branch=master
[coverage-status-url]: https://codecov.io/gh/bcoin-org/bcoin?branch=master
[circleci-status-img]: https://circleci.com/gh/bcoin-org/bcoin/tree/master.svg?style=shield
[circleci-status-url]: https://circleci.com/gh/bcoin-org/bcoin/tree/master
