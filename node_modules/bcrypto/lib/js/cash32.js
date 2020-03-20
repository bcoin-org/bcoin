/*!
 * cash32.js - cashaddr for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
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
 *   https://github.com/bitcoincashorg/spec/blob/master/cashaddr.md
 *   https://github.com/Bitcoin-ABC/bitcoin-abc/blob/master/src/cashaddr.cpp
 */

'use strict';

const assert = require('../internal/assert');

/**
 * Constants
 */

const POOL105 = Buffer.allocUnsafe(105);
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

const CHECKSUM_MASK = [0x00000007, 0xffffffff];

const GENERATOR = [
  0x00000098, 0xf2bc8e61,
  0x00000079, 0xb76d99e2,
  0x000000f3, 0x3e5fb3c4,
  0x000000ae, 0x2eabe2a8,
  0x0000001e, 0x4f43e470
];

/**
 * Update checksum
 * @ignore
 * @param {Number[]} chk
 * @param {Number} x
 * @returns {Number[]} -- new checksum
 */

function polymod(pre, x) {
  const c = pre;

  // b = c >> 35
  const b = c[0] >>> 3;

  // c = (c & CHECKSUM_MASK) << 5
  c[0] &= CHECKSUM_MASK[0];
  c[1] &= CHECKSUM_MASK[1];
  c[0] <<= 5;
  c[0] |= c[1] >>> 27;
  c[1] <<= 5;

  for (let i = 0; i < 5; i++) {
    if ((b >>> i) & 1) {
      // c ^= GENERATOR[i]
      c[0] ^= GENERATOR[i * 2 + 0];
      c[1] ^= GENERATOR[i * 2 + 1];
    }
  }

  // c ^= x
  c[1] ^= x;

  return c;
}

/**
 * Serialize data to cash32.
 * @param {String} prefix
 * @param {Buffer} data - 5bit serialized
 * @returns {String}
 */

function serialize(prefix, data) {
  assert(typeof prefix === 'string');
  assert(Buffer.isBuffer(data));

  const chk = [0, 1];

  let upper = false;
  let lower = false;
  let str = '';

  for (let i = 0; i < prefix.length; i++) {
    let ch = prefix.charCodeAt(i);

    if ((ch & 0xff00) || (ch >>> 5) === 0)
      throw new Error('Invalid cash32 character.');

    if (ch >= 0x61 && ch <= 0x7a) {
      lower = true;
    } else if (ch >= 0x41 && ch <= 0x5a) {
      upper = true;
      ch = (ch - 0x41) + 0x61;
    } else if (ch >= 0x30 && ch <= 0x39) {
      throw new Error('Invalid cash32 prefix.');
    }

    polymod(chk, ch & 0x1f);

    str += String.fromCharCode(ch);
  }

  if (lower && upper)
    throw new Error('Invalid cash32 prefix.');

  polymod(chk, 0);
  str += ':';

  for (let i = 0; i < data.length; i++) {
    const ch = data[i];

    if ((ch >>> 5) !== 0)
      throw new Error('Invalid cash32 value.');

    polymod(chk, ch);

    str += CHARSET[ch];
  }

  for (let i = 0; i < 8; i++)
    polymod(chk, 0);

  chk[1] ^= 1;

  // i = 0, shift = 35
  str += CHARSET[(chk[0] >>> 3) & 0x1f];

  for (let i = 1; i < 7; i++) {
    const shift = (7 - i) * 5;
    const v = (chk[1] >>> shift) | (chk[0] << (32 - shift));

    str += CHARSET[v & 0x1f];
  }

  // i = 7, shift = 0
  str += CHARSET[chk[1] & 0x1f];

  return str;
}

/**
 * Decode cash32 string.
 * @param {String} str
 * @param {String} defaultPrefix (lowercase and w/o numbers)
 * @returns {Array} [prefix, data]
 */

function deserialize(str, defaultPrefix) {
  assert(typeof str === 'string');
  assert(typeof defaultPrefix === 'string');

  if (str.length < 8 || str.length > 196) // 83 + 1 + 112
    throw new Error('Invalid cash32 data length.');

  let lower = false;
  let upper = false;
  let number = false;
  let plen = 0;

  // Process lower/upper, make sure we have prefix.
  for (let i = 0; i < str.length; i++) {
    const ch = str.charCodeAt(i);

    if (ch >= 0x61 && ch <= 0x7a) {
      lower = true;
      continue;
    }

    if (ch >= 0x41 && ch <= 0x5a) {
      upper = true;
      continue;
    }

    if (ch >= 0x30 && ch <= 0x39) {
      number = true;
      continue;
    }

    if (ch === 0x3a) { // :
      if (number || i === 0 || i > 83)
        throw new Error('Invalid cash32 prefix.');

      if (plen !== 0)
        throw new Error('Invalid cash32 separators.');

      plen = i;

      continue;
    }

    throw new Error('Invalid cash32 character.');
  }

  if (upper && lower)
    throw new Error('Invalid cash32 casing.');

  // Process checksum.
  const chk = [0, 1];

  let prefix;

  if (plen === 0) {
    prefix = defaultPrefix.toLowerCase();
  } else {
    prefix = str.substring(0, plen).toLowerCase();
    plen += 1;
  }

  // Process prefix.
  for (let i = 0; i < prefix.length; i++) {
    const ch = prefix.charCodeAt(i);

    polymod(chk, (ch | 0x20) & 0x1f);
  }

  polymod(chk, 0);

  const dlen = str.length - plen;

  if (dlen <= 8 || dlen > 112)
    throw new Error('Invalid cash32 data length.');

  const data = Buffer.allocUnsafe(dlen);

  for (let i = plen; i < str.length; i++) {
    const ch = str.charCodeAt(i);
    const v = (ch & 0xff80) ? -1 : TABLE[ch];

    if (v === -1)
      throw new Error('Invalid cash32 character.');

    polymod(chk, v);

    if (i + 8 < str.length)
      data[i - plen] = v;
  }

  const valid = chk[0] === 0 && chk[1] === 1 && prefix === defaultPrefix;

  if (!valid)
    throw new Error('Invalid cash32 checksum.');

  return [prefix, data.slice(0, -8)];
}

/**
 * Test whether a string is a cash32 string.
 * @param {String} str
 * @returns {Boolean}
 */

function is(str, defaultPrefix) {
  assert(typeof str === 'string');
  assert(typeof defaultPrefix === 'string');

  try {
    deserialize(str, defaultPrefix);
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
      throw new Error('Non standard length.');
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
  // There are 4 bits available for the version (2 ^ 4 = 16)
  assert((type & 0x0f) === type);
  assert(Buffer.isBuffer(hash));

  if (prefix.length === 0 || prefix.length > 83)
    throw new Error('Invalid cash32 prefix.');

  const size = encodedSize(hash.length);
  const data = Buffer.allocUnsafe(hash.length + 1);
  data[0] = (type << 3) | size;
  hash.copy(data, 1);

  const output = POOL105;
  const converted = convert(data, 0, output, 0, 8, 5, true);

  return serialize(prefix, converted);
}

/**
 * Deserialize data from cash32 address.
 * @param {String} str
 * @param {String} defaultPrefix (lowercase and w/o numbers)
 * @returns {Array}
 */

function decode(str, defaultPrefix = 'bitcoincash') {
  const [prefix, data] = deserialize(str, defaultPrefix);
  const extrabits = (data.length * 5) & 7;

  if (extrabits >= 5)
    throw new Error('Invalid padding in data.');

  const last = data[data.length - 1];
  const mask = (1 << extrabits) - 1;

  if (last & mask)
    throw new Error('Non zero padding.');

  const output = data;
  const converted = convert(data, 0, output, 0, 5, 8, false);

  const type = (converted[0] >>> 3) & 0x1f;
  const hash = converted.slice(1);

  let size = 20 + 4 * (converted[0] & 0x03);

  if (converted[0] & 0x04)
    size *= 2;

  if (size !== hash.length)
    throw new Error('Invalid cash32 data length.');

  return [prefix, type, hash];
}

/**
 * Test whether a string is a cash32 string.
 * @param {String} str
 * @param {String} defaultPrefix (lowercase and w/o numbers)
 * @returns {Boolean}
 */

function test(str, defaultPrefix = 'bitcoincash') {
  assert(typeof str === 'string');
  assert(typeof defaultPrefix === 'string');

  try {
    decode(str, defaultPrefix);
  } catch (e) {
    return false;
  }

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
