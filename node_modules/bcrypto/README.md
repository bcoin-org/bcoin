# bcrypto

[![Build Status][circleci-status-img]][circleci-status-url]

The missing crypto module for Node.js. Bcrypto provides you with a consistent
interface across Node.js and the browser. It is implemented as a
[Node.js addon][addon] for C libraries [libtorsion][libtorsion] (with
support for openssl and libgmp) and [libsecp256k1][libsecp256k1] with
corresponding implementations in JavaScript.

## Usage

```js
const random = require('bcrypto/lib/random');
const entropy = random.randomBytes(32);

const hash256 = require('bcrypto/lib/hash256');
const digest = hash256.digest(Buffer.alloc(32, 0x00));
```

## API

See the `./lib` directory for available modules and APIs.

## Implementations

|                              | nodejs (linux)    | nodejs (macos)    | nodejs (win)      | browser |
| :--------------------------- |:------------------| :-----------------|:------------------|:--------|
| aead                         | c (libtorsion¹)   | c (libtorsion¹)   | c (libtorsion¹)   | js      |
| aes                          | c (openssl)       | c (openssl)       | c (openssl)       | js      |
| bcrypt                       | js                | js                | js                | js      |
| blake2b{160,256,384,512}     | c (libtorsion)    | c (libtorsion)    | c (libtorsion)    | js      |
| blake2s{128,160,224,256}     | c (libtorsion)    | c (libtorsion)    | c (libtorsion)    | js      |
| bn                           | js w/ bigint      | js w/ bigint      | js w/ bigint      | js      |
| chacha20                     | c (libtorsion¹)   | c (libtorsion¹)   | c (libtorsion¹)   | js      |
| cshake{128,256}              | c (libtorsion¹)   | c (libtorsion¹)   | c (libtorsion¹)   | js      |
| ctr-drbg                     | js                | js                | js                | js      |
| dsa                          | c (libtorsion²)   | c (libtorsion²)   | c (libtorsion)    | js      |
| eb2k                         | js                | js                | js                | js      |
| ecies                        | c (libtorsion¹)   | c (libtorsion¹)   | c (libtorsion¹)   | js      |
| ed25519                      | c (libtorsion)    | c (libtorsion)    | c (libtorsion)    | js      |
| ed448                        | c (libtorsion)    | c (libtorsion)    | c (libtorsion)    | js      |
| gost94                       | c (libtorsion)    | c (libtorsion)    | c (libtorsion)    | js      |
| hash160                      | c (libtorsion³)   | c (libtorsion³)   | c (libtorsion)    | js      |
| hash256                      | c (libtorsion³)   | c (libtorsion³)   | c (libtorsion)    | js      |
| hash-drbg                    | js                | js                | js                | js      |
| hkdf                         | js                | js                | js                | js      |
| hmac-drbg                    | js                | js                | js                | js      |
| keccak/sha3{224,256,384,512} | c (libtorsion¹)   | c (libtorsion¹)   | c (libtorsion¹)   | js      |
| kmac{128,256}                | c (libtorsion¹)   | c (libtorsion¹)   | c (libtorsion¹)   | js      |
| md{2,4,5}                    | c (libtorsion)    | c (libtorsion)    | c (libtorsion)    | js      |
| md5sha1                      | c (libtorsion)    | c (libtorsion)    | c (libtorsion)    | js      |
| merkle                       | js                | js                | js                | js      |
| mrkl                         | js                | js                | js                | js      |
| murmur3                      | c                 | c                 | c                 | js      |
| p{192,224,256,384,521}       | c (libtorsion)    | c (libtorsion)    | c (libtorsion)    | js      |
| pbkdf2                       | c (libtorsion)    | c (libtorsion)    | c (libtorsion)    | js      |
| pgp                          | js                | js                | js                | js      |
| poly1305                     | c (libtorsion)    | c (libtorsion)    | c (libtorsion)    | js      |
| random                       | c (openssl)       | c (openssl)       | c (openssl)       | js      |
| rc4                          | js                | js                | js                | js      |
| ripemd160                    | c (libtorsion)    | c (libtorsion)    | c (libtorsion)    | js      |
| rsa                          | c (libtorsion²)   | c (libtorsion²)   | c (libtorsion)    | js      |
| rsaies                       | c (libtorsion¹)   | c (libtorsion¹)   | c (libtorsion¹)   | js      |
| salsa20                      | c (libtorsion¹)   | c (libtorsion¹)   | c (libtorsion¹)   | js      |
| schnorr                      | c (libtorsion)    | c (libtorsion)    | c (libtorsion)    | js      |
| scrypt                       | c (libtorsion)    | c (libtorsion)    | c (libtorsion)    | js      |
| secp256k1                    | c (libsecp256k1⁴) | c (libsecp256k1⁴) | c (libsecp256k1⁴) | js      |
| sha1                         | c (libtorsion)    | c (libtorsion)    | c (libtorsion)    | js      |
| sha{256,384,512}             | c (libtorsion³)   | c (libtorsion³)   | c (libtorsion)    | js      |
| shake{128,256}               | c (libtorsion¹)   | c (libtorsion¹)   | c (libtorsion¹)   | js      |
| siphash                      | c (libtorsion)    | c (libtorsion)    | c (libtorsion)    | js      |
| ssh                          | js                | js                | js                | js      |
| whirlpool                    | c (libtorsion)    | c (libtorsion)    | c (libtorsion)    | js      |
| x25519                       | c (libtorsion)    | c (libtorsion)    | c (libtorsion)    | js      |
| x448                         | c (libtorsion)    | c (libtorsion)    | c (libtorsion)    | js      |

### Footnotes
1. with assembly for x64
2. with libgmp and openssl (only libgmp on electron)
3. with openssl (except on electron)
4. optionally with libtorsion

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
