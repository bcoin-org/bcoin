/*!
 * bech32.js - bech32 for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on sipa/bech32:
 *   Copyright (c) 2017, Pieter Wuille (MIT License).
 *   https://github.com/sipa/bech32
 *
 * Resources:
 *   https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
 *   https://github.com/sipa/bech32/blob/master/ref/c/segwit_addr.c
 *   https://github.com/bitcoin/bitcoin/blob/master/src/bech32.cpp
 */

'use strict';

const assert = require('../internal/assert');

/**
 * Constants
 */

const POOL65 = Buffer.alloc(65);
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
 * Update checksum.
 * @ignore
 * @param {Number} c
 * @returns {Number}
 */

function polymod(c) {
  const b = c >>> 25;

  return ((c & 0x1ffffff) << 5)
    ^ (0x3b6a57b2 & -((b >> 0) & 1))
    ^ (0x26508e6d & -((b >> 1) & 1))
    ^ (0x1ea119fa & -((b >> 2) & 1))
    ^ (0x3d4233dd & -((b >> 3) & 1))
    ^ (0x2a1462b3 & -((b >> 4) & 1));
}

/**
 * Encode hrp and data as a bech32 string.
 * @param {String} hrp
 * @param {Buffer} data
 * @returns {String}
 */

function serialize(hrp, data) {
  assert(typeof hrp === 'string');
  assert(Buffer.isBuffer(data));

  if (hrp.length === 0 || hrp.length > 83)
    throw new Error('Invalid bech32 human-readable part.');

  if (hrp.length + 1 + data.length + 6 > 90)
    throw new Error('Invalid bech32 data length.');

  let str = '';
  let chk = 1;
  let i;

  for (i = 0; i < hrp.length; i++) {
    const ch = hrp.charCodeAt(i);

    if (ch < 33 || ch > 126)
      throw new Error('Invalid bech32 character.');

    if (ch >= 65 && ch <= 90)
      throw new Error('Invalid bech32 character.');

    chk = polymod(chk) ^ (ch >> 5);
  }

  chk = polymod(chk);

  for (let i = 0; i < hrp.length; i++) {
    const ch = hrp.charCodeAt(i);

    chk = polymod(chk) ^ (ch & 0x1f);

    str += hrp[i];
  }

  str += '1';

  for (let i = 0; i < data.length; i++) {
    const ch = data[i];

    if (ch >> 5)
      throw new Error('Invalid bech32 value.');

    chk = polymod(chk) ^ ch;

    str += CHARSET[ch];
  }

  for (let i = 0; i < 6; i++)
    chk = polymod(chk);

  chk ^= 1;

  for (let i = 0; i < 6; i++)
    str += CHARSET[(chk >>> ((5 - i) * 5)) & 0x1f];

  return str;
}

/**
 * Decode a bech32 string.
 * @param {String} str
 * @returns {Array} [hrp, data]
 */

function deserialize(str) {
  assert(typeof str === 'string');

  if (str.length < 8 || str.length > 90)
    throw new Error('Invalid bech32 string length.');

  let lower = false;
  let upper = false;
  let hlen = 0;

  for (let i = 0; i < str.length; i++) {
    const ch = str.charCodeAt(i);

    if (ch < 33 || ch > 126)
      throw new Error('Invalid bech32 character.');

    if (ch >= 97 && ch <= 122)
      lower = true;
    else if (ch >= 65 && ch <= 90)
      upper = true;
    else if (ch === 49)
      hlen = i;
  }

  if (hlen === 0)
    throw new Error('Invalid bech32 human-readable part.');

  const dlen = str.length - (hlen + 1);

  if (dlen < 6)
    throw new Error('Invalid bech32 data length.');

  if (lower && upper)
    throw new Error('Invalid bech32 casing.');

  let chk = 1;
  let hrp = '';

  for (let i = 0; i < hlen; i++) {
    let ch = str.charCodeAt(i);

    if (ch >= 65 && ch <= 90)
      ch += 32;

    chk = polymod(chk) ^ (ch >> 5);

    hrp += String.fromCharCode(ch);
  }

  chk = polymod(chk);

  for (let i = 0; i < hlen; i++)
    chk = polymod(chk) ^ (str.charCodeAt(i) & 0x1f);

  const data = Buffer.alloc(dlen - 6);

  let j = 0;

  for (let i = hlen + 1; i < str.length; i++) {
    const val = TABLE[str.charCodeAt(i)];

    if (val === -1)
      throw new Error('Invalid bech32 character.');

    chk = polymod(chk) ^ val;

    if (i < str.length - 6)
      data[j++] = val;
  }

  if (chk !== 1)
    throw new Error('Invalid bech32 checksum.');

  assert(j === data.length);

  return [hrp, data];
}

/**
 * Test whether a string is a bech32 string.
 * @param {String} str
 * @returns {Boolean}
 */

function is(str) {
  assert(typeof str === 'string');

  try {
    deserialize(str);
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

  let acc = 0;
  let bits = 0;
  let i = srcoff;
  let j = dstoff;

  for (; i < src.length; i++) {
    acc = (acc << srcbits) | src[i];
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
    if (((acc << left) & mask) || bits >= srcbits)
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
 * Serialize data to bech32 address.
 * @param {String} hrp
 * @param {Number} version
 * @param {Buffer} hash
 * @returns {String}
 */

function encode(hrp, version, hash) {
  assert(typeof hrp === 'string');
  assert((version >>> 0) === version);
  assert(Buffer.isBuffer(hash));

  if (version > 31)
    throw new Error('Invalid bech32 version.');

  if (hash.length < 2 || hash.length > 40)
    throw new Error('Invalid bech32 data length.');

  const out = POOL65;

  out[0] = version;

  const data = convert(out, 1, 5, hash, 0, 8, true);

  return serialize(hrp, data);
}

/**
 * Deserialize data from bech32 address.
 * @param {String} addr
 * @returns {Array}
 */

function decode(addr) {
  const [hrp, data] = deserialize(addr);

  if (data.length === 0 || data.length > 65)
    throw new Error('Invalid bech32 data length.');

  const version = data[0];

  if (version > 31)
    throw new Error('Invalid bech32 version.');

  const output = data; // Works because dstbits > srcbits.
  const hash = convert(output, 0, 8, data, 1, 5, false);

  if (hash.length < 2 || hash.length > 40)
    throw new Error('Invalid bech32 data length.');

  return [hrp, version, hash];
}

/**
 * Test whether a string is a bech32 string.
 * @param {String} addr
 * @returns {Boolean}
 */

function test(addr) {
  assert(typeof addr === 'string');

  try {
    decode(addr);
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
