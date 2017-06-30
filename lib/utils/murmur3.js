/*!
 * murmur3.js - murmur3 hash for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const native = require('../native').binding;

/**
 * Murmur3 hash.
 * @alias module:utils.murmur3
 * @param {Buffer} data
 * @param {Number} seed
 * @returns {Number}
 */

function murmur3(data, seed) {
  let tail = data.length - (data.length % 4);
  let c1 = 0xcc9e2d51;
  let c2 = 0x1b873593;
  let h1 = seed;
  let k1;

  for (let i = 0; i < tail; i += 4) {
    k1 = (data[i + 3] << 24)
      | (data[i + 2] << 16)
      | (data[i + 1] << 8)
      | data[i];
    k1 = mul32(k1, c1);
    k1 = rotl32(k1, 15);
    k1 = mul32(k1, c2);
    h1 ^= k1;
    h1 = rotl32(h1, 13);
    h1 = sum32(mul32(h1, 5), 0xe6546b64);
  }

  k1 = 0;
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

  if (h1 < 0)
    h1 += 0x100000000;

  return h1;
}

if (native)
  murmur3 = native.murmur3;

function mul32(a, b) {
  let alo = a & 0xffff;
  let blo = b & 0xffff;
  let ahi = a >>> 16;
  let bhi = b >>> 16;
  let r, lo, hi;

  lo = alo * blo;
  hi = (ahi * blo + bhi * alo) & 0xffff;

  hi += lo >>> 16;
  lo &= 0xffff;
  r = (hi << 16) | lo;

  if (r < 0)
    r += 0x100000000;

  return r;
}

function sum32(a, b) {
  let r = (a + b) & 0xffffffff;

  if (r < 0)
    r += 0x100000000;

  return r;
}

function rotl32(w, b) {
  return (w << b) | (w >>> (32 - b));
}

/**
 * Expose
 */

exports = murmur3;
exports.murmur3 = murmur3;
exports.mul32 = mul32;
exports.sum32 = sum32;
exports.rotl32 = rotl32;
module.exports = exports;
