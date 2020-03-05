/*!
 * base58.js - base58 for bcrypto
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on bitcoin/bitcoin:
 *   Copyright (c) 2009-2019, The Bitcoin Core Developers (MIT License).
 *   Copyright (c) 2009-2019, The Bitcoin Developers (MIT License).
 *   https://github.com/bitcoin/bitcoin
 *
 * Resources:
 *   https://github.com/bitcoin/bitcoin/blob/master/src/base58.cpp
 */

'use strict';

const assert = require('../internal/assert');

/*
 * Constants
 */

const CHARSET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const TABLE = [
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1,  0,  1,  2,  3,  4,  5,  6,  7,  8, -1, -1, -1, -1, -1, -1,
  -1,  9, 10, 11, 12, 13, 14, 15, 16, -1, 17, 18, 19, 20, 21, -1,
  22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, -1, -1, -1, -1, -1,
  -1, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, -1, 44, 45, 46,
  47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, -1, -1, -1, -1, -1
];

/**
 * Encode a base58 string.
 * @param {Buffer} data
 * @returns {String}
 */

function encode(data) {
  assert(Buffer.isBuffer(data));

  let zeroes = 0;
  let i = 0;

  for (; i < data.length; i++) {
    if (data[i] !== 0)
      break;

    zeroes += 1;
  }

  const b58 = Buffer.allocUnsafe(((data.length * 138 / 100) | 0) + 1);

  b58.fill(0);

  let length = 0;

  for (; i < data.length; i++) {
    let carry = data[i];
    let j = 0;

    for (let k = b58.length - 1; k >= 0; k--, j++) {
      if (carry === 0 && j >= length)
        break;

      carry += 256 * b58[k];
      b58[k] = carry % 58;
      carry = (carry / 58) | 0;
    }

    assert(carry === 0);

    length = j;
  }

  i = b58.length - length;

  while (i < b58.length && b58[i] === 0)
    i += 1;

  let str = '';

  for (let j = 0; j < zeroes; j++)
    str += '1';

  for (; i < b58.length; i++)
    str += CHARSET[b58[i]];

  return str;
}

/**
 * Decode a base58 string.
 * @param {String} str
 * @returns {Buffer}
 * @throws on non-base58 character.
 */

function decode(str) {
  assert(typeof str === 'string');

  let zeroes = 0;
  let i = 0;

  for (; i < str.length; i++) {
    if (str[i] !== '1')
      break;

    zeroes += 1;
  }

  const b256 = Buffer.allocUnsafe(((str.length * 733) / 1000 | 0) + 1);

  b256.fill(0);

  let length = 0;

  for (; i < str.length; i++) {
    const ch = str.charCodeAt(i);
    const v = (ch & 0xff80) ? -1 : TABLE[ch];

    if (v === -1)
      throw new Error('Non-base58 character.');

    let carry = v;
    let j = 0;

    for (let k = b256.length - 1; k >= 0; k--, j++) {
      if (carry === 0 && j >= length)
        break;

      carry += 58 * b256[k];
      b256[k] = carry & 0xff;
      carry >>>= 8;
    }

    assert(carry === 0);

    length = j;
  }

  i = 0;

  while (i < b256.length && b256[i] === 0)
    i += 1;

  const out = Buffer.allocUnsafe(zeroes + (b256.length - i));

  let j;

  for (j = 0; j < zeroes; j++)
    out[j] = 0;

  while (i < b256.length)
    out[j++] = b256[i++];

  return out;
}

/**
 * Test whether the string is a base58 string.
 * @param {String} str
 * @returns {Buffer}
 */

function test(str) {
  assert(typeof str === 'string');

  for (let i = 0; i < str.length; i++) {
    const ch = str.charCodeAt(i);

    if (ch & 0xff80)
      return false;

    if (TABLE[ch] === -1)
      return false;
  }

  return true;
}

/*
 * Expose
 */

exports.native = 0;
exports.encode = encode;
exports.decode = decode;
exports.test = test;
