/*!
 * murmur3.js - murmur3 hash for bcrypto
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/MurmurHash
 *   https://github.com/aappleby/smhasher
 */

'use strict';

const assert = require('../internal/assert');

/**
 * Murmur3 hash.
 * @param {Buffer} data
 * @param {Number} seed
 * @returns {Number}
 */

function sum(data, seed) {
  assert(Buffer.isBuffer(data));
  assert(typeof seed === 'number');

  const tail = data.length - (data.length & 3);
  const c1 = 0xcc9e2d51;
  const c2 = 0x1b873593;

  let h1 = seed | 0;

  for (let i = 0; i < tail; i += 4) {
    let k1 = readU32(data, i);

    k1 = mul32(k1, c1);
    k1 = rotl32(k1, 15);
    k1 = mul32(k1, c2);
    h1 ^= k1;
    h1 = rotl32(h1, 13);
    h1 = (mul32(h1, 5) + 0xe6546b64) | 0;
  }

  let k1 = 0;

  switch (data.length & 3) {
    case 3:
      k1 ^= data[tail + 2] << 16;
    case 2:
      k1 ^= data[tail + 1] << 8;
    case 1:
      k1 ^= data[tail + 0];
      k1 = mul32(k1, c1);
      k1 = rotl32(k1, 15);
      k1 = mul32(k1, c2);
      h1 ^= k1;
  }

  h1 ^= data.length;
  h1 ^= h1 >>> 16;
  h1 = mul32(h1, 0x85ebca6b);
  h1 ^= h1 >>> 13;
  h1 = mul32(h1, 0xc2b2ae35);
  h1 ^= h1 >>> 16;

  return h1 >>> 0;
}

/**
 * Murmur3 hash.
 * @param {Buffer} data
 * @param {Number} n
 * @param {Number} tweak
 * @returns {Number}
 */

function tweak(data, n, tweak) {
  assert(typeof n === 'number');
  assert(typeof tweak === 'number');

  const seed = mul32(n, 0xfba4c795) + (tweak | 0);

  return sum(data, seed);
}

/*
 * Helpers
 */

function mul32(a, b) {
  const alo = a & 0xffff;
  const blo = b & 0xffff;
  const ahi = a >>> 16;
  const bhi = b >>> 16;
  const lo = alo * blo;
  const hi = ahi * blo + bhi * alo + (lo >>> 16);

  return (hi << 16) | (lo & 0xffff);
}

function rotl32(w, b) {
  return (w << b) | (w >>> (32 - b));
}

function readU32(data, off) {
  return (data[off++]
        + data[off++] * 0x100
        + data[off++] * 0x10000
        + data[off] * 0x1000000);
}

/**
 * Expose
 */

exports.native = 0;
exports.sum = sum;
exports.tweak = tweak;
