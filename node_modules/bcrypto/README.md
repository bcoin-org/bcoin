# bcrypto

[![Build Status][circleci-status-img]][circleci-status-url]

The missing crypto module for node.js. bcrypto provides you with a consistent
interface accross node.js and the browser.

Bcrypto takes advantage of the fact that node.js is statically linked with
OpenSSL. There are a number of features in OpenSSL which are not directly
exposed in the node.js API. As such, the node.js backend for bcrypto adds very
little in terms of memory usage (all of these features are already _in_ the
node.js binary).

## Usage

TODO

## API

TODO

## Contribution and License Agreement

If you contribute code to this project, you are implicitly allowing your code
to be distributed under the MIT license. You are also implicitly verifying that
all code is your original work. `</legalese>`

## License

- Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).

See LICENSE for more info.

[circleci-status-img]: https://circleci.com/gh/bcoin-org/bcrypto/tree/master.svg?style=shield
[circleci-status-url]: https://circleci.com/gh/bcoin-org/bcrypto/tree/master
