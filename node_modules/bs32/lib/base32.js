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

const assert = require('bsert');

/*
 * Constants
 */

const CHARSET = 'abcdefghijklmnopqrstuvwxyz234567';
const TABLE = [
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, 26, 27, 28, 29, 30, 31, -1, -1, -1, -1, -1, -1, -1, -1,
  -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
  15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
  -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
  15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1
];

const CHARSET_HEX = '0123456789abcdefghijklmnopqrstuv';
const TABLE_HEX = [
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
   0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1,
  -1, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
  25, 26, 27, 28, 29, 30, 31, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
  25, 26, 27, 28, 29, 30, 31, -1, -1, -1, -1, -1, -1, -1, -1, -1
];

const PADDING = [0, 6, 4, 3, 1];

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
 * Encode a base32hex string.
 * @param {Buffer} data
 * @param {Boolean} [pad=false]
 * @returns {String}
 */

function encodeHex(data, pad = false) {
  return _encode(data, CHARSET_HEX, pad);
}

/**
 * Encode a base32 string.
 * @private
 * @param {Buffer} data
 * @param {String} charset
 * @param {Boolean} [pad=false]
 * @returns {String}
 */

function _encode(data, charset, pad = false) {
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
 * @param {String} str
 * @param {Boolean} [unpad=false]
 * @returns {Buffer}
 */

function decode(str, unpad = false) {
  return _decode(str, TABLE, unpad);
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

  const data = Buffer.allocUnsafe((str.length * 5 + 7) / 8 | 0);

  let mode = 0;
  let left = 0;
  let j = 0;
  let i = 0;

  for (; i < str.length; i++) {
    const ch = str.charCodeAt(i);
    const v = (ch & 0xff80) ? -1 : table[ch];

    if (v === -1)
      break;

    switch (mode) {
      case 0:
        left = v;
        mode = 1;
        break;
      case 1:
        data[j++] = (left << 3) | (v >>> 2);
        left = v & 3;
        mode = 2;
        break;
      case 2:
        left = left << 5 | v;
        mode = 3;
        break;
      case 3:
        data[j++] = (left << 1) | (v >>> 4);
        left = v & 15;
        mode = 4;
        break;
      case 4:
        data[j++] = (left << 4) | (v >>> 1);
        left = v & 1;
        mode = 5;
        break;
      case 5:
        left = left << 5 | v;
        mode = 6;
        break;
      case 6:
        data[j++] = (left << 2) | (v >>> 3);
        left = v & 7;
        mode = 7;
        break;
      case 7:
        data[j++] = (left << 5) | v;
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

  return data.slice(0, j);
}

/**
 * Test a base32 string.
 * @param {String} str
 * @param {Boolean} [unpad=false]
 * @returns {Buffer}
 */

function test(str, unpad = false) {
  try {
    decode(str, unpad);
    return true;
  } catch (e) {
    return false;
  }
}

/**
 * Test a base32 hex string.
 * @param {String} str
 * @param {Boolean} [unpad=false]
 * @returns {Buffer}
 */

function testHex(str, unpad = false) {
  try {
    decodeHex(str, unpad);
    return true;
  } catch (e) {
    return false;
  }
}

/*
 * Expose
 */

exports.encode = encode;
exports.encodeHex = encodeHex;
exports.decode = decode;
exports.decodeHex = decodeHex;
exports.test = test;
exports.testHex = testHex;
