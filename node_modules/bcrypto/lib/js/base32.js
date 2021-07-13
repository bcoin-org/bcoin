/*!
 * base32.js - base32 for bcrypto
 * Copyright (c) 2014-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on bitcoin/bitcoin:
 *   Copyright (c) 2009-2019, The Bitcoin Core Developers (MIT License).
 *   Copyright (c) 2009-2019, The Bitcoin Developers (MIT License).
 *   https://github.com/bitcoin/bitcoin
 *
 * Resources:
 *   https://tools.ietf.org/html/rfc4648
 *   https://github.com/bitcoin/bitcoin/blob/11d486d/src/utilstrencodings.cpp#L230
 */

'use strict';

const assert = require('../internal/assert');

/*
 * Constants
 */

const CHARSET = 'abcdefghijklmnopqrstuvwxyz234567';

const TABLE = [
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, 26, 27, 28, 29, 30, 31,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1,  0,  1,  2,  3,  4,  5,  6,
   7,  8,  9, 10, 11, 12, 13, 14,
  15, 16, 17, 18, 19, 20, 21, 22,
  23, 24, 25, -1, -1, -1, -1, -1,
  -1,  0,  1,  2,  3,  4,  5,  6,
   7,  8,  9, 10, 11, 12, 13, 14,
  15, 16, 17, 18, 19, 20, 21, 22,
  23, 24, 25, -1, -1, -1, -1, -1
];

const CHARSET_HEX = '0123456789abcdefghijklmnopqrstuv';

const TABLE_HEX = [
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
   0,  1,  2,  3,  4,  5,  6,  7,
   8,  9, -1, -1, -1, -1, -1, -1,
  -1, 10, 11, 12, 13, 14, 15, 16,
  17, 18, 19, 20, 21, 22, 23, 24,
  25, 26, 27, 28, 29, 30, 31, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, 10, 11, 12, 13, 14, 15, 16,
  17, 18, 19, 20, 21, 22, 23, 24,
  25, 26, 27, 28, 29, 30, 31, -1,
  -1, -1, -1, -1, -1, -1, -1, -1
];

const PADDING = [0, 6, 4, 3, 1];

/**
 * Encode a base32 string.
 * @private
 * @param {Buffer} data
 * @param {String} charset
 * @param {Boolean} [pad=false]
 * @returns {String}
 */

function _encode(data, charset, pad) {
  assert(Buffer.isBuffer(data));
  assert(typeof pad === 'boolean');

  let str = '';
  let mode = 0;
  let left = 0;

  for (let i = 0; i < data.length; i++) {
    const ch = data[i];

    switch (mode) {
      case 0:
        str += charset[ch >>> 3];
        left = (ch & 7) << 2;
        mode = 1;
        break;
      case 1:
        str += charset[left | (ch >>> 6)];
        str += charset[(ch >>> 1) & 31];
        left = (ch & 1) << 4;
        mode = 2;
        break;
      case 2:
        str += charset[left | (ch >>> 4)];
        left = (ch & 15) << 1;
        mode = 3;
        break;
      case 3:
        str += charset[left | (ch >>> 7)];
        str += charset[(ch >>> 2) & 31];
        left = (ch & 3) << 3;
        mode = 4;
        break;
      case 4:
        str += charset[left | (ch >>> 5)];
        str += charset[ch & 31];
        mode = 0;
        break;
    }
  }

  if (mode > 0) {
    str += charset[left];
    if (pad) {
      for (let i = 0; i < PADDING[mode]; i++)
        str += '=';
    }
  }

  return str;
}

/**
 * Decode a base32 string.
 * @private
 * @param {String} str
 * @param {Array} table
 * @param {Boolean} [unpad=false]
 * @returns {Buffer}
 */

function _decode(str, table, unpad) {
  assert(typeof str === 'string');
  assert(typeof unpad === 'boolean');

  const size = _decodeSize(str);
  const data = Buffer.alloc(size);

  let mode = 0;
  let left = 0;
  let j = 0;
  let i = 0;

  for (; i < str.length; i++) {
    const ch = str.charCodeAt(i);

    if (ch & 0xff80)
      throw new Error('Invalid base32 string.');

    const val = table[ch];

    if (val === -1)
      break;

    switch (mode) {
      case 0:
        left = val;
        mode = 1;
        break;
      case 1:
        data[j++] = (left << 3) | (val >>> 2);
        left = val & 3;
        mode = 2;
        break;
      case 2:
        left = (left << 5) | val;
        mode = 3;
        break;
      case 3:
        data[j++] = (left << 1) | (val >>> 4);
        left = val & 15;
        mode = 4;
        break;
      case 4:
        data[j++] = (left << 4) | (val >>> 1);
        left = val & 1;
        mode = 5;
        break;
      case 5:
        left = (left << 5) | val;
        mode = 6;
        break;
      case 6:
        data[j++] = (left << 2) | (val >>> 3);
        left = val & 7;
        mode = 7;
        break;
      case 7:
        data[j++] = (left << 5) | val;
        left = 0;
        mode = 0;
        break;
    }
  }

  if (mode === 1 || mode === 3 || mode === 6)
    throw new Error('Invalid base32 string.');

  if (left > 0)
    throw new Error('Invalid base32 string.');

  if (str.length !== i + (-mode & 7) * unpad)
    throw new Error('Invalid base32 string.');

  for (; i < str.length; i++) {
    const ch = str.charCodeAt(i);

    if (ch !== 0x3d)
      throw new Error('Invalid base32 string.');
  }

  assert(j === size);

  return data;
}

/**
 * Calculate decoding size.
 * @private
 * @param {String} str
 * @returns {Number}
 */

function _decodeSize(str) {
  let len = str.length;

  for (let i = 0; i < 6 && len > 0; i++) {
    if (str[len - 1] === '=')
      len -= 1;
  }

  let size = (len >>> 3) * 5;

  switch (len & 7) {
    case 7:
      size += 1;
    case 6: // Invalid.
    case 5:
      size += 1;
    case 4:
      size += 1;
    case 3: // Invalid.
    case 2:
      size += 1;
  }

  return size;
}

/**
 * Test a base32 string.
 * @private
 * @param {String} str
 * @param {Array} table
 * @param {Boolean} [unpad=false]
 * @returns {Boolean}
 */

function _test(str, table, unpad) {
  assert(typeof str === 'string');
  assert(typeof unpad === 'boolean');

  let i = 0;

  for (; i < str.length; i++) {
    const ch = str.charCodeAt(i);

    if (ch & 0xff80)
      return false;

    if (table[ch] === -1)
      break;
  }

  const mode = i & 7;

  switch (mode) {
    case 1:
      return false;
    case 2:
      if (table[str.charCodeAt(i - 1)] & 3)
        return false;
      break;
    case 3:
      return false;
    case 4:
      if (table[str.charCodeAt(i - 1)] & 15)
        return false;
      break;
    case 5:
      if (table[str.charCodeAt(i - 1)] & 1)
        return false;
      break;
    case 6:
      return false;
    case 7:
      if (table[str.charCodeAt(i - 1)] & 7)
        return false;
      break;
  }

  if (str.length !== i + (-mode & 7) * unpad)
    return false;

  for (; i < str.length; i++) {
    const ch = str.charCodeAt(i);

    if (ch !== 0x3d)
      return false;
  }

  return true;
}

/**
 * Encode a base32 string.
 * @param {Buffer} data
 * @param {Boolean} [pad=false]
 * @returns {String}
 */

function encode(data, pad = false) {
  return _encode(data, CHARSET, pad);
}

/**
 * Decode a base32 string.
 * @param {String} str
 * @param {Boolean} [unpad=false]
 * @returns {Buffer}
 */

function decode(str, unpad = false) {
  return _decode(str, TABLE, unpad);
}

/**
 * Test a base32 string.
 * @param {String} str
 * @param {Boolean} [unpad=false]
 * @returns {Buffer}
 */

function test(str, unpad = false) {
  return _test(str, TABLE, unpad);
}

/**
 * Encode a base32hex string.
 * @param {Buffer} data
 * @param {Boolean} [pad=false]
 * @returns {String}
 */

function encodeHex(data, pad = false) {
  return _encode(data, CHARSET_HEX, pad);
}

/**
 * Decode a base32hex string.
 * @param {String} str
 * @param {Boolean} [unpad=false]
 * @returns {Buffer}
 */

function decodeHex(str, unpad = false) {
  return _decode(str, TABLE_HEX, unpad);
}

/**
 * Test a base32 hex string.
 * @param {String} str
 * @param {Boolean} [unpad=false]
 * @returns {Buffer}
 */

function testHex(str, unpad = false) {
  return _test(str, TABLE_HEX, unpad);
}

/*
 * Expose
 */

exports.native = 0;
exports.encode = encode;
exports.decode = decode;
exports.test = test;
exports.encodeHex = encodeHex;
exports.decodeHex = decodeHex;
exports.testHex = testHex;
