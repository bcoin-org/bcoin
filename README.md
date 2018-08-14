# Bcoin

[![Build Status][circleci-status-img]][circleci-status-url]
[![Coverage Status][coverage-status-img]][coverage-status-url]

__NOTE__: The latest release of bcoin contains a non-backward compatible change
to the rest API. Please read the [changelog]'s "migrating" section for more
details.

---

**Bcoin** is an alternative implementation of the bitcoin protocol, written in
node.js.

Bcoin is well tested and aware of all known consensus rules. It is currently
used in production as the consensus backend and wallet system for
[purse.io][purse].

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
- REST Docs: http://bcoin.io/api-docs/index.html
- Docs: [docs/](docs/README.md)

## Development & Testing

Development dependencies are not included in `package.json` and are expected to be installed on the development machine. This is to increase efficiency of auditing dependencies, as the code only need to be audited once, rather than for each repository and module.

Install development dependencies _(if necessary)_:
```
npm install -g mocha@5.2.0 eslint@5.1.0 istanbul@1.1.0-alpha.1 jsdoc@3.5.5
```

To run tests:
```
npm run test
```

To run tests against a JS backend _(as with the case of a web browser)_:
```
npm run test-browser
```

To generate a test coverage report:
```
npm run test-ci
```
And open `./coverage/lcov-report/index.html` in your preferred web browser.

To generate automated documentation:
```
npm run docs
```
And open `./docs/reference/` in your preferred web browser.

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

[coverage-status-img]: https://codecov.io/gh/bcoin-org/bcoin/badge.svg?branch=master
[coverage-status-url]: https://codecov.io/gh/bcoin-org/bcoin?branch=master
[circleci-status-img]: https://circleci.com/gh/bcoin-org/bcoin/tree/master.svg?style=shield
[circleci-status-url]: https://circleci.com/gh/bcoin-org/bcoin/tree/master
