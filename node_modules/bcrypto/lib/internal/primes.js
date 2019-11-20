/*!
 * primes.js - Prime number generation for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on golang/go:
 *   Copyright (c) 2009 The Go Authors. All rights reserved.
 *   https://github.com/golang/go
 *
 * Parts of this software are based on indutny/miller-rabin:
 *   Copyright (c) 2014, Fedor Indutny (MIT License).
 *   https://github.com/indutny/miller-rabin
 *
 * Resources:
 *   https://github.com/golang/go/blob/master/src/crypto/rsa/rsa.go
 *   https://github.com/golang/go/blob/master/src/math/big/prime.go
 *   https://github.com/golang/go/blob/master/src/math/big/int.go
 *   https://github.com/golang/go/blob/master/src/math/big/nat.go
 *   https://github.com/golang/go/blob/master/src/crypto/rand/util.go
 *   https://github.com/indutny/miller-rabin/blob/master/lib/mr.js
 */

'use strict';

const assert = require('bsert');
const BN = require('../bn.js');
const rng = require('../random');

/*
 * Constants
 */

const smallPrimes = new Uint8Array([
   3,  5,  7,
  11, 13, 17,
  19, 23, 29,
  31, 37, 41,
  43, 47, 53
]);

const smallPrimesProduct = new BN('16294579238595022365', 10);

const primeBitMaskLo = 0
  | (1 << 2)
  | (1 << 3)
  | (1 << 5)
  | (1 << 7)
  | (1 << 11)
  | (1 << 13)
  | (1 << 17)
  | (1 << 19)
  | (1 << 23)
  | (1 << 29)
  | (1 << 31);

const primeBitMaskHi = 0
  | (1 << (37 - 32))
  | (1 << (41 - 32))
  | (1 << (43 - 32))
  | (1 << (47 - 32))
  | (1 << (53 - 32))
  | (1 << (59 - 32))
  | (1 << (61 - 32));

const primesA = new BN(3 * 5 * 7 * 11 * 13 * 17 * 19 * 23 * 37);
const primesB = new BN(29 * 31 * 41 * 43 * 47 * 53);

// https://github.com/golang/go/blob/aadaec5/src/crypto/rand/util.go#L31
function randomPrime(bits, reps = 20) {
  assert((bits >>> 0) === bits);
  assert((reps >>> 0) === reps);
  assert(bits >= 2);

  let b = bits % 8;

  if (b === 0)
    b = 8;

  const len = (bits + 7) >>> 3;
  const bytes = Buffer.allocUnsafe(len);

  for (;;) {
    rng.randomFill(bytes, 0, len);

    bytes[0] &= (1 << b) - 1;

    if (b >= 2) {
      bytes[0] |= 3 << (b - 2);
    } else {
      bytes[0] |= 1;
      if (bytes.length > 1)
        bytes[1] |= 0x80;
    }

    bytes[bytes.length - 1] |= 1;

    const p = new BN(bytes);
    const mod = p.mod(smallPrimesProduct);

next:
    for (let delta = 0; delta < (1 << 20); delta += 2) {
      const m = mod.addn(delta);

      for (let i = 0; i < smallPrimes.length; i++) {
        const prime = smallPrimes[i];
        if (m.modrn(prime) === 0 && (bits > 6 || m.cmpn(prime) !== 0))
          continue next;
      }

      if (delta > 0)
        p.iaddn(delta);

      break;
    }

    if (p.bitLength() !== bits)
      continue;

    if (!probablyPrime(p, reps))
      continue;

    return p;
  }
}

// https://github.com/golang/go/blob/aadaec5/src/math/big/prime.go#L26
function probablyPrime(x, reps) {
  assert(x instanceof BN);

  if (x.isNeg() || x.isZero())
    return false;

  if (x.cmpn(64) < 0) {
    const w = x.andln(0xff);

    if (w > 31)
      return (primeBitMaskHi & (1 << (w - 32))) !== 0;

    return (primeBitMaskLo & (1 << w)) !== 0;
  }

  if (!x.isOdd())
    return false;

  const ra = x.umod(primesA).toNumber();
  const rb = x.umod(primesB).toNumber();

  if (ra % 3 === 0
      || ra % 5 === 0
      || ra % 7 === 0
      || ra % 11 === 0
      || ra % 13 === 0
      || ra % 17 === 0
      || ra % 19 === 0
      || ra % 23 === 0
      || ra % 37 === 0
      || rb % 29 === 0
      || rb % 31 === 0
      || rb % 41 === 0
      || rb % 43 === 0
      || rb % 47 === 0
      || rb % 53 === 0) {
    return false;
  }

  if (!x.isPrime(rng, reps))
    return false;

  return true;
}

/*
 * Expose
 */

exports.randomPrime = randomPrime;
exports.probablyPrime = probablyPrime;
