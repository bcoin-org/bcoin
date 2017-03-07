/*!
 * base58.js - base58 for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/**
 * @module utils/base58
 */

var native = require('./native').binding;
var assert = require('assert');

/*
 * Base58
 */

var base58 = ''
  + '123456789'
  + 'ABCDEFGHJKLMNPQRSTUVWXYZ'
  + 'abcdefghijkmnopqrstuvwxyz';

var unbase58 = {};

for (var i = 0; i < base58.length; i++)
  unbase58[base58[i]] = i;

/**
 * Encode a base58 string.
 * @see https://github.com/bitcoin/bitcoin/blob/master/src/base58.cpp
 * @param {Buffer} data
 * @returns {Base58String}
 */

exports.encode = function encode(data) {
  var zeroes = 0;
  var length = 0;
  var str = '';
  var i, b58, carry, j, k;

  for (i = 0; i < data.length; i++) {
    if (data[i] !== 0)
      break;
    zeroes++;
  }

  b58 = new Buffer(((data.length * 138 / 100) | 0) + 1);
  b58.fill(0);

  for (; i < data.length; i++) {
    carry = data[i];
    j = 0;

    for (k = b58.length - 1; k >= 0; k--, j++) {
      if (carry === 0 && j >= length)
        break;
      carry += 256 * b58[k];
      b58[k] = carry % 58;
      carry = carry / 58 | 0;
    }

    assert(carry === 0);
    length = j;
  }

  i = b58.length - length;
  while (i < b58.length && b58[i] === 0)
    i++;

  for (j = 0; j < zeroes; j++)
    str += '1';

  for (; i < b58.length; i++)
    str += base58[b58[i]];

  return str;
};

if (native)
  exports.encode = native.toBase58;

/**
 * Decode a base58 string.
 * @see https://github.com/bitcoin/bitcoin/blob/master/src/base58.cpp
 * @param {Base58String} str
 * @returns {Buffer}
 * @throws on non-base58 character.
 */

exports.decode = function decode(str) {
  var zeroes = 0;
  var length = 0;
  var i = 0;
  var b256, ch, carry, j, k, out;

  for (i = 0; i < str.length; i++) {
    if (str[i] !== '1')
      break;
    zeroes++;
  }

  b256 = new Buffer(((str.length * 733) / 1000 | 0) + 1);
  b256.fill(0);

  for (; i < str.length; i++) {
    ch = unbase58[str[i]];
    if (ch == null)
      throw new Error('Non-base58 character.');

    carry = ch;
    j = 0;

    for (k = b256.length - 1; k >= 0; k--, j++) {
      if (carry === 0 && j >= length)
        break;
      carry += 58 * b256[k];
      b256[k] = carry % 256;
      carry = carry / 256 | 0;
    }

    assert(carry === 0);
    length = j;
  }

  i = 0;
  while (i < b256.length && b256[i] === 0)
    i++;

  out = new Buffer(zeroes + (b256.length - i));

  for (j = 0; j < zeroes; j++)
    out[j] = 0;

  while (i < b256.length)
    out[j++] = b256[i++];

  return out;
};

if (native)
  exports.decode = native.fromBase58;
