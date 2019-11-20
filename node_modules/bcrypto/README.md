# bcrypto

[![Build Status][circleci-status-img]][circleci-status-url]

The missing crypto module for node.js. bcrypto provides you with a consistent
interface accross node.js and the browser.

Bcrypto takes advantage of the fact that node.js is statically linked with
OpenSSL. There are a number of features in OpenSSL which are not directly
exposed in the node.js API. As such, the node.js backend for bcrypto adds very
little in terms of memory usage (all of these features are already _in_ the
node.js binary).

## Features

Bcrypto adds a number of features over the standard node.js crypto module.

Low-level APIs for popular public key algorithms:

- DSA
- RSA (PKCS1v1.5, OAEP, PSS)
- ECDSA (p192, p224, p256, p384, p512, secp256k1)
- EdDSA (ed25519, ed448)

Bcrypto includes specialized and optimized support specifically for [secp256k1]
and [ed25519]. Note that these crypto systems are preferred over the NIST
curves (see the [safecurves.cr.yp.to][safecurves] "rigidity" section).

Modern ciphers:

- ChaCha20+Poly1305

Modern hash algorithms:

- SHA3/Keccak
- BLAKE2

Key Derivation:

- bcrypt
- scrypt
- hkdf

Encoding:

- ASN.1 Parsing & Serialization
- SSH key parsing
- PGP keyring parsing

## Usage

``` js
const bcrypto = require('bcrypto');
// TODO
```

## API

TODO

## Contribution and License Agreement

If you contribute code to this project, you are implicitly allowing your code
to be distributed under the MIT license. You are also implicitly verifying that
all code is your original work. `</legalese>`

## License

- Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).

See LICENSE for more info.

[secp256k1]: https://github.com/bitcoin-core/secp256k1
[ed25519]: https://github.com/floodyberry/ed25519-donna
[safecurves]: https://safecurves.cr.yp.to/rigid.html

[circleci-status-img]: https://circleci.com/gh/bcoin-org/bcrypto/tree/master.svg?style=shield
[circleci-status-url]: https://circleci.com/gh/bcoin-org/bcrypto/tree/master
