# bcrypto

![node.js](https://github.com/bcoin-org/bcrypto/workflows/node.js/badge.svg)

The missing crypto module for Node.js. Bcrypto provides you with a consistent
interface across Node.js and the browser. It is implemented as a [Node.js
addon][addon] for C libraries [libtorsion][libtorsion] and
[libsecp256k1][libsecp256k1] with corresponding implementations in JavaScript.

## Usage

```js
const rng = require('bcrypto/lib/random');
const entropy = rng.randomBytes(32);

const Hash256 = require('bcrypto/lib/hash256');
const digest = Hash256.digest(Buffer.alloc(32, 0xaa));
```

## API

See the `./lib` directory for available modules and APIs.

## Implementations

|                              | nodejs (linux)    | nodejs (macos)    | nodejs (win)      | browser |
| :--------------------------- |:------------------| :-----------------|:------------------|:--------|
| aead                         | c (libtorsion¹)   | c (libtorsion¹)   | c (libtorsion)    | js      |
| aes                          | c (libtorsion)    | c (libtorsion)    | c (libtorsion)    | js      |
| bcrypt                       | c (libtorsion)    | c (libtorsion)    | c (libtorsion)    | js      |
| blake2b{160,256,384,512}     | c (libtorsion)    | c (libtorsion)    | c (libtorsion)    | js      |
| blake2s{128,160,224,256}     | c (libtorsion)    | c (libtorsion)    | c (libtorsion)    | js      |
| bn                           | js w/ bigint      | js w/ bigint      | js w/ bigint      | js      |
| chacha20                     | c (libtorsion¹)   | c (libtorsion¹)   | c (libtorsion)    | js      |
| cshake{128,256}              | c (libtorsion¹)   | c (libtorsion¹)   | c (libtorsion)    | js      |
| ctr-drbg                     | c (libtorsion)    | c (libtorsion)    | c (libtorsion)    | js      |
| dsa                          | c (libtorsion)    | c (libtorsion)    | c (libtorsion)    | js      |
| eb2k                         | c (libtorsion)    | c (libtorsion)    | c (libtorsion)    | js      |
| ecies                        | c (libtorsion¹)   | c (libtorsion¹)   | c (libtorsion)    | js      |
| ed25519                      | c (libtorsion)    | c (libtorsion)    | c (libtorsion)    | js      |
| ed448                        | c (libtorsion)    | c (libtorsion)    | c (libtorsion)    | js      |
| gost94                       | c (libtorsion)    | c (libtorsion)    | c (libtorsion)    | js      |
| hash160                      | c (libtorsion¹)   | c (libtorsion¹)   | c (libtorsion)    | js      |
| hash256                      | c (libtorsion¹)   | c (libtorsion¹)   | c (libtorsion)    | js      |
| hash-drbg                    | c (libtorsion)    | c (libtorsion)    | c (libtorsion)    | js      |
| hkdf                         | c (libtorsion)    | c (libtorsion)    | c (libtorsion)    | js      |
| hmac-drbg                    | c (libtorsion)    | c (libtorsion)    | c (libtorsion)    | js      |
| keccak/sha3{224,256,384,512} | c (libtorsion¹)   | c (libtorsion¹)   | c (libtorsion)    | js      |
| kmac{128,256}                | c (libtorsion¹)   | c (libtorsion¹)   | c (libtorsion)    | js      |
| md{2,4,5}                    | c (libtorsion)    | c (libtorsion)    | c (libtorsion)    | js      |
| md5sha1                      | c (libtorsion)    | c (libtorsion)    | c (libtorsion)    | js      |
| merkle                       | js                | js                | js                | js      |
| mrkl                         | js                | js                | js                | js      |
| murmur3                      | c (libtorsion)    | c (libtorsion)    | c (libtorsion)    | js      |
| p{192,224,256,384,521}       | c (libtorsion)    | c (libtorsion)    | c (libtorsion)    | js      |
| pbkdf2                       | c (libtorsion)    | c (libtorsion)    | c (libtorsion)    | js      |
| pgp                          | js                | js                | js                | js      |
| poly1305                     | c (libtorsion)    | c (libtorsion)    | c (libtorsion)    | js      |
| random                       | c (openssl²)      | c (openssl²)      | c (openssl²)      | js³     |
| rc4                          | c (libtorsion)    | c (libtorsion)    | c (libtorsion)    | js      |
| ripemd160                    | c (libtorsion)    | c (libtorsion)    | c (libtorsion)    | js      |
| rsa                          | c (libtorsion)    | c (libtorsion)    | c (libtorsion)    | js      |
| rsaies                       | c (libtorsion¹)   | c (libtorsion¹)   | c (libtorsion)    | js      |
| salsa20                      | c (libtorsion¹)   | c (libtorsion¹)   | c (libtorsion)    | js      |
| schnorr                      | c (libtorsion)    | c (libtorsion)    | c (libtorsion)    | js      |
| scrypt                       | c (libtorsion)    | c (libtorsion)    | c (libtorsion)    | js      |
| secp256k1                    | c (libsecp256k1²) | c (libsecp256k1²) | c (libsecp256k1²) | js      |
| sha1                         | c (libtorsion)    | c (libtorsion)    | c (libtorsion)    | js      |
| sha{224,256,384,512}         | c (libtorsion¹)   | c (libtorsion¹)   | c (libtorsion)    | js      |
| shake{128,256}               | c (libtorsion¹)   | c (libtorsion¹)   | c (libtorsion)    | js      |
| siphash                      | c (libtorsion)    | c (libtorsion)    | c (libtorsion)    | js      |
| ssh                          | js                | js                | js                | js      |
| whirlpool                    | c (libtorsion)    | c (libtorsion)    | c (libtorsion)    | js      |
| x25519                       | c (libtorsion)    | c (libtorsion)    | c (libtorsion)    | js      |
| x448                         | c (libtorsion)    | c (libtorsion)    | c (libtorsion)    | js      |

### Footnotes

1. with x86-64 assembly
2. optionally with libtorsion
3. using the webcrypto api

## Contribution and License Agreement

If you contribute code to this project, you are implicitly allowing your code
to be distributed under the MIT license. You are also implicitly verifying that
all code is your original work. `</legalese>`

## License

- Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).

See LICENSE for more info.

[circleci-status-img]: https://circleci.com/gh/bcoin-org/bcrypto/tree/master.svg?style=shield
[circleci-status-url]: https://circleci.com/gh/bcoin-org/bcrypto/tree/master
[libtorsion]: https://github.com/bcoin-org/libtorsion
[libsecp256k1]: https://github.com/bitcoin-core/secp256k1
[addon]: https://nodejs.org/api/addons.html
