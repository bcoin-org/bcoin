/*!
 * base16.js - base16 for javascript
 * Copyright (c) 2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://tools.ietf.org/html/rfc4648
 */

'use strict';

const assert = require('../internal/assert');

/*
 * Constants
 */

const CHARSET = '0123456789abcdef';

const TABLE = [
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
   0,  1,  2,  3,  4,  5,  6,  7,
   8,  9, -1, -1, -1, -1, -1, -1,
  -1, 10, 11, 12, 13, 14, 15, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, 10, 11, 12, 13, 14, 15, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1
];

/*
 * Encoding
 */

function _encode(data, endian) {
  assert(Buffer.isBuffer(data));

  let len = data.length;
  let i = endian < 0 ? len - 1 : 0;
  let str = '';

  while (len--) {
    str += CHARSET[data[i] >> 4];
    str += CHARSET[data[i] & 15];

    i += endian;
  }

  return str;
}

/*
 * Decoding
 */

function _decode(str, endian) {
  assert(typeof str === 'string');

  let len = str.length;
  let i = endian < 0 ? len - 2 : 0;
  let j = 0;
  let z = 0;

  if (len & 1)
    throw new Error('Invalid hex string.');

  len >>>= 1;
  endian *= 2;

  const data = Buffer.alloc(len);

  while (len--) {
    const c1 = str.charCodeAt(i + 0);
    const c2 = str.charCodeAt(i + 1);
    const hi = TABLE[c1 & 0x7f];
    const lo = TABLE[c2 & 0x7f];

    z |= c1 | c2 | hi | lo;

    data[j++] = (hi << 4) | lo;

    i += endian;
  }

  // Check for errors at the end.
  if (z & 0xffffff80)
    throw new Error('Invalid hex string.');

  return data;
}

/*
 * Testing
 */

function _test(str) {
  assert(typeof str === 'string');

  if (str.length & 1)
    return false;

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
 * Base16
 */

function encode(data) {
  return _encode(data, 1);
}

function decode(str) {
  return _decode(str, 1);
}

function test(str) {
  return _test(str);
}

/*
 * Base16 (Little Endian)
 */

function encodeLE(data) {
  return _encode(data, -1);
}

function decodeLE(str) {
  return _decode(str, -1);
}

function testLE(str) {
  return _test(str);
}

/*
 * Expose
 */

exports.native = 0;
exports.encode = encode;
exports.decode = decode;
exports.test = test;
exports.encodeLE = encodeLE;
exports.decodeLE = decodeLE;
exports.testLE = testLE;
