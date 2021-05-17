/*!
 * cash32.js - cashaddr for bcrypto
 * Copyright (c) 2018-2020, The Bcoin Developers (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on Bitcoin-ABC/bitcoin-abc:
 *   Copyright (c) 2009-2019, The Bitcoin Developers (MIT License).
 *   Copyright (c) 2009-2017, The Bitcoin Core Developers (MIT License).
 *   https://github.com/Bitcoin-ABC/bitcoin-abc
 *
 * Parts of this software are based on sipa/bech32:
 *   Copyright (c) 2017, Pieter Wuille (MIT License).
 *   https://github.com/sipa/bech32
 *
 * Resources:
 *   https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/cashaddr.md
 *   https://github.com/Bitcoin-ABC/bitcoin-abc/blob/master/src/cashaddr.cpp
 *   https://github.com/Bitcoin-ABC/bitcoin-abc/blob/master/src/cashaddrenc.cpp
 *   https://github.com/Bitcoin-ABC/bitcoin-abc/blob/master/src/util/strencodings.h
 */

'use strict';

const assert = require('../internal/assert');

/**
 * Constants
 */

const POOL104 = Buffer.alloc(104);
const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

const TABLE = [
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  15, -1, 10, 17, 21, 20, 26, 30,
   7,  5, -1, -1, -1, -1, -1, -1,
  -1, 29, -1, 24, 13, 25,  9,  8,
  23, -1, 18, 22, 31, 27, 19, -1,
   1,  0,  3, 16, 11, 28, 12, 14,
   6,  4,  2, -1, -1, -1, -1, -1,
  -1, 29, -1, 24, 13, 25,  9,  8,
  23, -1, 18, 22, 31, 27, 19, -1,
   1,  0,  3, 16, 11, 28, 12, 14,
   6,  4,  2, -1, -1, -1, -1, -1
];

/**
 * Update checksum
 * @ignore
 * @param {Number[]} c
 * @param {Number} d
 */

function polymod(c, d) {
  // b = c >> 35
  const b = c[1] >>> 3;

  // c = (c & 0x7ffffffff) << 5
  c[0] &= 0xffffffff;
  c[1] &= 0x00000007;
  c[1] <<= 5;
  c[1] |= c[0] >>> 27;
  c[0] <<= 5;

  // c ^= 0x98f2bc8e61 & -((b >> 0) & 1)
  if ((b >>> 0) & 1) {
    c[0] ^= 0xf2bc8e61;
    c[1] ^= 0x00000098;
  }

  // c ^= 0x79b76d99e2 & -((b >> 1) & 1)
  if ((b >>> 1) & 1) {
    c[0] ^= 0xb76d99e2;
    c[1] ^= 0x00000079;
  }

  // c ^= 0xf33e5fb3c4 & -((b >> 2) & 1)
  if ((b >>> 2) & 1) {
    c[0] ^= 0x3e5fb3c4;
    c[1] ^= 0x000000f3;
  }

  // c ^= 0xae2eabe2a8 & -((b >> 3) & 1)
  if ((b >>> 3) & 1) {
    c[0] ^= 0x2eabe2a8;
    c[1] ^= 0x000000ae;
  }

  // c ^= 0x1e4f43e470 & -((b >> 4) & 1)
  if ((b >>> 4) & 1) {
    c[0] ^= 0x4f43e470;
    c[1] ^= 0x0000001e;
  }

  // c ^= d
  c[0] ^= d;
}

/**
 * Serialize data to cash32.
 * @param {String} prefix
 * @param {Buffer} data
 * @returns {String}
 */

function serialize(prefix, data) {
  assert(typeof prefix === 'string');
  assert(Buffer.isBuffer(data));

  if (prefix.length === 0 || prefix.length > 83)
    throw new Error('Invalid cash32 prefix.');

  if (data.length > 104)
    throw new Error('Invalid cash32 data.');

  const chk = [1, 0];

  let str = '';

  for (let i = 0; i < prefix.length; i++) {
    const ch = prefix.charCodeAt(i);

    if (ch < 97 || ch > 122)
      throw new Error('Invalid cash32 prefix.');

    polymod(chk, ch & 0x1f);

    str += String.fromCharCode(ch);
  }

  polymod(chk, 0);

  str += ':';

  for (let i = 0; i < data.length; i++) {
    const ch = data[i];

    if (ch >> 5)
      throw new Error('Invalid cash32 value.');

    polymod(chk, ch);

    str += CHARSET[ch];
  }

  for (let i = 0; i < 8; i++)
    polymod(chk, 0);

  chk[0] ^= 1;

  // First two rounds shift by 35 and 30.
  str += CHARSET[(chk[1] >>> 3) & 0x1f];
  str += CHARSET[((chk[0] >>> 30) | (chk[1] << 2)) & 0x1f];

  // Now 25 down to 0.
  for (let i = 2; i < 8; i++)
    str += CHARSET[(chk[0] >>> ((7 - i) * 5)) & 0x1f];

  return str;
}

/**
 * Decode cash32 string.
 * @param {String} str
 * @param {String} fallback
 * @returns {Array} [prefix, data]
 */

function deserialize(str, fallback) {
  assert(typeof str === 'string');
  assert(typeof fallback === 'string');

  if (str.length < 8 || str.length > 196) // 83 + 1 + 112
    throw new Error('Invalid cash32 string.');

  let lower = false;
  let upper = false;
  let number = false;
  let plen = 0;

  for (let i = 0; i < str.length; i++) {
    const ch = str.charCodeAt(i);

    if (ch >= 97 && ch <= 122) {
      lower = true;
      continue;
    }

    if (ch >= 65 && ch <= 90) {
      upper = true;
      continue;
    }

    if (ch >= 48 && ch <= 57) {
      number = true;
      continue;
    }

    if (ch === 58) {
      if (number || i === 0 || plen !== 0)
        throw new Error('Invalid cash32 prefix.');

      plen = i;

      continue;
    }

    throw new Error('Invalid cash32 string.');
  }

  if (lower && upper)
    throw new Error('Invalid cash32 casing.');

  const chk = [1, 0];

  let prefix = '';
  let dlen;

  if (plen === 0) {
    if (fallback.length === 0 || fallback.length > 83)
      throw new Error('Invalid cash32 prefix.');

    for (let i = 0; i < fallback.length; i++) {
      const ch = fallback.charCodeAt(i);

      if (ch < 97 || ch > 122)
        throw new Error('Invalid cash32 prefix.');

      polymod(chk, ch & 0x1f);
    }

    prefix = fallback;
    dlen = str.length;
  } else {
    if (plen > 83)
      throw new Error('Invalid cash32 prefix.');

    for (let i = 0; i < plen; i++) {
      const ch = str.charCodeAt(i) | 32;

      polymod(chk, ch & 0x1f);

      prefix += String.fromCharCode(ch);
    }

    dlen = str.length - (plen + 1);
  }

  if (dlen < 8 || dlen > 112)
    throw new Error('Invalid cash32 data.');

  polymod(chk, 0);

  const data = Buffer.alloc(dlen - 8);

  let j = 0;

  for (let i = str.length - dlen; i < str.length; i++) {
    const val = TABLE[str.charCodeAt(i)];

    if (val === -1)
      throw new Error('Invalid cash32 character.');

    polymod(chk, val);

    if (i < str.length - 8)
      data[j++] = val;
  }

  if (chk[0] !== 1 || chk[1] !== 0)
    throw new Error('Invalid cash32 checksum.');

  assert(j === data.length);

  return [prefix, data];
}

/**
 * Test whether a string is a cash32 string.
 * @param {String} str
 * @param {String} fallback
 * @returns {Boolean}
 */

function is(str, fallback) {
  assert(typeof str === 'string');
  assert(typeof fallback === 'string');

  try {
    deserialize(str, fallback);
    return true;
  } catch (e) {
    return false;
  }
}

/**
 * Convert serialized data to another base.
 * @param {Buffer} dst
 * @param {Number} dstoff
 * @param {Number} dstbits
 * @param {Buffer} src
 * @param {Number} srcoff
 * @param {Number} srcbits
 * @param {Boolean} pad
 * @returns {Buffer}
 */

function convert(dst, dstoff, dstbits, src, srcoff, srcbits, pad) {
  assert(Buffer.isBuffer(dst));
  assert((dstoff >>> 0) === dstoff);
  assert((dstbits >>> 0) === dstbits);
  assert(Buffer.isBuffer(src));
  assert((srcoff >>> 0) === srcoff);
  assert((srcbits >>> 0) === srcbits);
  assert(typeof pad === 'boolean');
  assert(dstbits >= 1 && dstbits <= 8);
  assert(srcbits >= 1 && srcbits <= 8);

  const mask = (1 << dstbits) - 1;
  const maxacc = (1 << (srcbits + dstbits - 1)) - 1;

  let acc = 0;
  let bits = 0;
  let i = srcoff;
  let j = dstoff;

  for (; i < src.length; i++) {
    acc = ((acc << srcbits) | src[i]) & maxacc;
    bits += srcbits;

    while (bits >= dstbits) {
      bits -= dstbits;
      dst[j++] = (acc >>> bits) & mask;
    }
  }

  const left = dstbits - bits;

  if (pad) {
    if (bits)
      dst[j++] = (acc << left) & mask;
  } else {
    if (bits >= srcbits || ((acc << left) & mask))
      throw new Error('Invalid bits.');
  }

  assert(j <= dst.length);

  return dst.slice(0, j);
}

/**
 * Calculate size required for bit conversion.
 * @param {Number} len
 * @param {Number} srcbits
 * @param {Number} dstbits
 * @param {Boolean} pad
 * @returns {Number}
 */

function convertSize(len, srcbits, dstbits, pad) {
  assert((len >>> 0) === len);
  assert((srcbits >>> 0) === srcbits);
  assert((dstbits >>> 0) === dstbits);
  assert(typeof pad === 'boolean');
  assert(srcbits >= 1 && srcbits <= 8);
  assert(dstbits >= 1 && dstbits <= 8);

  return ((len * srcbits + (dstbits - 1) * (pad | 0)) / dstbits) >>> 0;
}

/**
 * Convert serialized data to another base.
 * @param {Buffer} data
 * @param {Number} srcbits
 * @param {Number} dstbits
 * @param {Boolean} pad
 * @returns {Buffer}
 */

function convertBits(data, srcbits, dstbits, pad) {
  assert(Buffer.isBuffer(data));

  const size = convertSize(data.length, srcbits, dstbits, pad);
  const out = Buffer.alloc(size);

  return convert(out, 0, dstbits, data, 0, srcbits, pad);
}

/**
 * Get cash32 encoded size.
 * @param {Number} size
 * @returns {Number}
 */

function encodedSize(size) {
  assert((size >>> 0) === size);

  switch (size) {
    case 20:
      return 0;
    case 24:
      return 1;
    case 28:
      return 2;
    case 32:
      return 3;
    case 40:
      return 4;
    case 48:
      return 5;
    case 56:
      return 6;
    case 64:
      return 7;
    default:
      throw new Error('Non-standard length.');
  }
}

/**
 * Serialize data to cash32
 * @param {String} prefix
 * @param {Number} type - (0 = P2PKH, 1 = P2SH)
 * @param {Buffer} hash
 * @returns {String}
 */

function encode(prefix, type, hash) {
  assert(typeof prefix === 'string');
  assert((type >>> 0) === type);
  assert(Buffer.isBuffer(hash));

  if (type > 15)
    throw new Error('Invalid cash32 type.');

  const size = encodedSize(hash.length);
  const data = Buffer.alloc(hash.length + 1);

  data[0] = (type << 3) | size;

  hash.copy(data, 1);

  const output = POOL104;
  const conv = convert(output, 0, 5, data, 0, 8, true);

  return serialize(prefix, conv);
}

/**
 * Deserialize data from cash32 address.
 * @param {String} addr
 * @param {String} expect
 * @returns {Array}
 */

function decode(addr, expect = 'bitcoincash') {
  const [prefix, conv] = deserialize(addr, expect);

  if (prefix !== expect)
    throw new Error('Invalid cash32 prefix.');

  if (conv.length === 0 || conv.length > 104)
    throw new Error('Invalid cash32 data.');

  const output = conv; // Works because dstbits > srcbits.
  const data = convert(output, 0, 8, conv, 0, 5, false);

  if (data.length === 0 || data.length > 1 + 64)
    throw new Error('Invalid cash32 data.');

  const type = (data[0] >> 3) & 31;
  const hash = data.slice(1);

  let size = 20 + 4 * (data[0] & 3);

  if (data[0] & 4)
    size *= 2;

  if (type > 15)
    throw new Error('Invalid cash32 type.');

  if (size !== hash.length)
    throw new Error('Invalid cash32 data length.');

  return [type, hash];
}

/**
 * Test whether a string is a cash32 string.
 * @param {String} addr
 * @param {String} expect
 * @returns {Boolean}
 */

function test(addr, expect = 'bitcoincash') {
  assert(typeof addr === 'string');
  assert(typeof expect === 'string');

  try {
    decode(addr, expect);
    return true;
  } catch (e) {
    return false;
  }
}

/*
 * Expose
 */

exports.native = 0;
exports.serialize = serialize;
exports.deserialize = deserialize;
exports.is = is;
exports.convertBits = convertBits;
exports.encode = encode;
exports.decode = decode;
exports.test = test;
