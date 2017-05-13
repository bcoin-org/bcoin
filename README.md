# Lcoin (Bcoin ported to Litecoin)

**Lcoin** is an alternative implementation of the litecoin protocol, written in
node.js.

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
$ git clone git://github.com/bcoin-org/lcoin.git
$ cd lcoin
$ npm install
$ ./bin/lcoin
```

See the [Beginner's Guide][guide] for more in-depth installation instructions.

## Documentation

- API Docs: http://bcoin.io/docs/
- REST Docs: https://github.com/bcoin-org/bcoin/wiki/REST-&-RPC-API
- Wiki: https://github.com/bcoin-org/bcoin/wiki

## Support

Join us on [freenode][freenode] in the [#bcoin][irc] channel.

## Disclaimer

Lcoin does not guarantee you against theft or lost funds due to bugs, mishaps,
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
[guide]: https://github.com/bcoin-org/bcoin/wiki/Beginner's-Guide
[freenode]: https://freenode.net/
[irc]: irc://irc.freenode.net/bcoin
