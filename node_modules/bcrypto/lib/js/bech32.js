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

const POOL66 = Buffer.allocUnsafe(66);
const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const TABLE = [
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
  -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
   1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
  -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
   1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1
];

/**
 * Update checksum.
 * @ignore
 * @param {Number} chk
 * @returns {Number}
 */

function polymod(pre) {
  const b = pre >>> 25;
  return ((pre & 0x1ffffff) << 5)
    ^ (-((b >>> 0) & 1) & 0x3b6a57b2)
    ^ (-((b >>> 1) & 1) & 0x26508e6d)
    ^ (-((b >>> 2) & 1) & 0x1ea119fa)
    ^ (-((b >>> 3) & 1) & 0x3d4233dd)
    ^ (-((b >>> 4) & 1) & 0x2a1462b3);
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

  let chk = 1;
  let i;

  for (i = 0; i < hrp.length; i++) {
    const ch = hrp.charCodeAt(i);

    if ((ch & 0xff00) || (ch >>> 5) === 0)
      throw new Error('Invalid bech32 character.');

    chk = polymod(chk) ^ (ch >>> 5);
  }

  if (i + 7 + data.length > 90)
    throw new Error('Invalid bech32 data length.');

  chk = polymod(chk);

  let str = '';

  for (let i = 0; i < hrp.length; i++) {
    const ch = hrp.charCodeAt(i);
    chk = polymod(chk) ^ (ch & 0x1f);
    str += hrp[i];
  }

  str += '1';

  for (let i = 0; i < data.length; i++) {
    const ch = data[i];

    if ((ch >>> 5) !== 0)
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

  let dlen = 0;

  while (dlen < str.length && str[(str.length - 1) - dlen] !== '1')
    dlen += 1;

  const hlen = str.length - (1 + dlen);

  if (1 + dlen >= str.length || dlen < 6)
    throw new Error('Invalid bech32 data length.');

  dlen -= 6;

  const data = Buffer.allocUnsafe(dlen);

  let chk = 1;
  let lower = false;
  let upper = false;
  let hrp = '';

  for (let i = 0; i < hlen; i++) {
    let ch = str.charCodeAt(i);

    if (ch < 0x21 || ch > 0x7e)
      throw new Error('Invalid bech32 character.');

    if (ch >= 0x61 && ch <= 0x7a) {
      lower = true;
    } else if (ch >= 0x41 && ch <= 0x5a) {
      upper = true;
      ch = (ch - 0x41) + 0x61;
    }

    hrp += String.fromCharCode(ch);
    chk = polymod(chk) ^ (ch >>> 5);
  }

  chk = polymod(chk);

  let i;
  for (i = 0; i < hlen; i++)
    chk = polymod(chk) ^ (str.charCodeAt(i) & 0x1f);

  i += 1;

  while (i < str.length) {
    const ch = str.charCodeAt(i);
    const v = (ch & 0xff80) ? -1 : TABLE[ch];

    if (v === -1)
      throw new Error('Invalid bech32 character.');

    if (ch >= 0x61 && ch <= 0x7a)
      lower = true;
    else if (ch >= 0x41 && ch <= 0x5a)
      upper = true;

    chk = polymod(chk) ^ v;

    if (i + 6 < str.length)
      data[i - (1 + hlen)] = v;

    i += 1;
  }

  if (lower && upper)
    throw new Error('Invalid bech32 casing.');

  if (chk !== 1)
    throw new Error('Invalid bech32 checksum.');

  return [hrp, data.slice(0, dlen)];
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
  } catch (e) {
    return false;
  }

  return true;
}

/**
 * Convert serialized data to another base.
 * @param {Buffer} input
 * @param {Number} i
 * @param {Buffer} output
 * @param {Number} j
 * @param {Number} frombits
 * @param {Number} tobits
 * @param {Boolean} pad
 * @returns {Buffer}
 */

function convert(input, i, output, j, frombits, tobits, pad) {
  assert(Buffer.isBuffer(input));
  assert((i >>> 0) === i);
  assert(Buffer.isBuffer(output));
  assert((j >>> 0) === j);
  assert((frombits & 0xff) === frombits);
  assert((tobits & 0xff) === tobits);
  assert(typeof pad === 'boolean');
  assert(frombits !== 0);
  assert(tobits !== 0);

  const maxv = (1 << tobits) - 1;

  let acc = 0;
  let bits = 0;

  for (; i < input.length; i++) {
    const value = input[i];

    if ((value >>> frombits) !== 0)
      throw new Error('Invalid bits.');

    acc = (acc << frombits) | value;
    bits += frombits;

    while (bits >= tobits) {
      bits -= tobits;
      output[j++] = (acc >>> bits) & maxv;
    }
  }

  if (pad) {
    if (bits)
      output[j++] = (acc << (tobits - bits)) & maxv;
  } else {
    if (bits >= frombits || ((acc << (tobits - bits)) & maxv))
      throw new Error('Invalid bits.');
  }

  assert(j <= output.length);

  return output.slice(0, j);
}

/**
 * Calculate size required for bit conversion.
 * @param {Number} len
 * @param {Number} frombits
 * @param {Number} tobits
 * @param {Boolean} pad
 * @returns {Number}
 */

function convertSize(len, frombits, tobits, pad) {
  assert((len >>> 0) === len);
  assert((frombits & 0xff) === frombits);
  assert((tobits & 0xff) === tobits);
  assert(typeof pad === 'boolean');
  assert(frombits !== 0);
  assert(tobits !== 0);

  let size = (len * frombits + (tobits - 1)) / tobits;

  size >>>= 0;

  if (pad)
    size += 1;

  return size;
}

/**
 * Convert serialized data to another base.
 * @param {Buffer} data
 * @param {Number} frombits
 * @param {Number} tobits
 * @param {Boolean} pad
 * @returns {Buffer}
 */

function convertBits(data, frombits, tobits, pad) {
  assert(Buffer.isBuffer(data));

  const size = convertSize(data.length, frombits, tobits, pad);
  const out = Buffer.allocUnsafe(size);

  return convert(data, 0, out, 0, frombits, tobits, pad);
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
  assert((version & 0xff) === version);
  assert(Buffer.isBuffer(hash));

  if (version < 0 || version > 31)
    throw new Error('Invalid bech32 version.');

  if (hash.length < 2 || hash.length > 40)
    throw new Error('Invalid bech32 data length.');

  const out = POOL66;
  out[0] = version;

  const data = convert(hash, 0, out, 1, 8, 5, true);

  return serialize(hrp, data);
}

/**
 * Deserialize data from bech32 address.
 * @param {String} str
 * @returns {Array}
 */

function decode(str) {
  const [hrp, data] = deserialize(str);

  if (data.length === 0 || data.length > 65)
    throw new Error('Invalid bech32 data length.');

  const version = data[0];

  if (version > 31)
    throw new Error('Invalid bech32 version.');

  const hash = convert(data, 1, data, 0, 5, 8, false);

  if (hash.length < 2 || hash.length > 40)
    throw new Error('Invalid bech32 data length.');

  return [hrp, version, hash];
}

/**
 * Test whether a string is a bech32 string.
 * @param {String} str
 * @returns {Boolean}
 */

function test(str) {
  assert(typeof str === 'string');

  let data;

  try {
    [, data] = deserialize(str);
  } catch (e) {
    return false;
  }

  if (data.length === 0 || data.length > 65)
    return false;

  const version = data[0];

  if (version > 31)
    return false;

  return true;
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
