/*!
 * primes.js - Prime number generation for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on golang/go:
 *   Copyright (c) 2009, The Go Authors. All rights reserved.
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

const assert = require('../internal/assert');
const BN = require('../bn');
const random = require('../random');

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

/*
 * Primality
 */

function randomPrime(bits, reps = 20, rng = random) {
  assert((bits >>> 0) === bits);
  assert((reps >>> 0) === reps);
  assert(rng != null);

  if (bits < 2)
    throw new Error('Prime must be at least 2 bits.');

  for (;;) {
    const p = BN.randomBits(rng, bits);

    p.setn(bits - 1, 1);
    p.setn(bits - 2, 1);
    p.setn(0, 1);

    const mod = p.mod(smallPrimesProduct);

next:
    for (let delta = 0; delta < (1 << 20); delta += 2) {
      const m = mod.addn(delta);

      for (let i = 0; i < smallPrimes.length; i++) {
        const prime = smallPrimes[i];

        if (m.modrn(prime) === 0 && (bits > 6 || m.cmpn(prime) !== 0))
          continue next;
      }

      p.iaddn(delta);

      break;
    }

    if (p.bitLength() !== bits)
      continue;

    if (!isProbablePrime(p, reps, rng))
      continue;

    return p;
  }
}

function isProbablePrime(x, reps, rng = random) {
  assert(x instanceof BN);

  if (x.sign() <= 0)
    return false;

  if (x.cmpn(64) < 0) {
    const w = x.word(0);

    if (w > 31)
      return (primeBitMaskHi & (1 << (w - 32))) !== 0;

    return (primeBitMaskLo & (1 << w)) !== 0;
  }

  if (x.isEven())
    return false;

  const ra = x.mod(primesA).toNumber();
  const rb = x.mod(primesB).toNumber();

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

  return x.isPrime(rng, reps);
}

function isSafePrime(x, reps, rng) {
  // Safe Prime (2p + 1).
  if (!isProbablePrime(x, reps, rng))
    return false;

  // Sophie Germain Prime (p).
  const p = x.subn(1).iushrn(1);

  if (!isProbablePrime(p, reps, rng))
    return false;

  return true;
}

/*
 * Expose
 */

exports.randomPrime = randomPrime;
exports.isProbablePrime = isProbablePrime;
exports.isSafePrime = isSafePrime;
