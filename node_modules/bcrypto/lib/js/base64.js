/*!
 * base64.js - base64 for javascript
 * Copyright (c) 2019-2020, Christopher Jeffrey (MIT License).
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

const CHARSET =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

const CHARSET_URL =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

const TABLE = [
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, 62, -1, -1, -1, 63,
  52, 53, 54, 55, 56, 57, 58, 59,
  60, 61, -1, -1, -1, -1, -1, -1,
  -1,  0,  1,  2,  3,  4,  5,  6,
   7,  8,  9, 10, 11, 12, 13, 14,
  15, 16, 17, 18, 19, 20, 21, 22,
  23, 24, 25, -1, -1, -1, -1, -1,
  -1, 26, 27, 28, 29, 30, 31, 32,
  33, 34, 35, 36, 37, 38, 39, 40,
  41, 42, 43, 44, 45, 46, 47, 48,
  49, 50, 51, -1, -1, -1, -1, -1
];

const TABLE_URL = [
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, 62, -1, -1,
  52, 53, 54, 55, 56, 57, 58, 59,
  60, 61, -1, -1, -1, -1, -1, -1,
  -1,  0,  1,  2,  3,  4,  5,  6,
   7,  8,  9, 10, 11, 12, 13, 14,
  15, 16, 17, 18, 19, 20, 21, 22,
  23, 24, 25, -1, -1, -1, -1, 63,
  -1, 26, 27, 28, 29, 30, 31, 32,
  33, 34, 35, 36, 37, 38, 39, 40,
  41, 42, 43, 44, 45, 46, 47, 48,
  49, 50, 51, -1, -1, -1, -1, -1
];

/*
 * Encoding
 */

function _encode(data, charset, pad) {
  assert(Buffer.isBuffer(data));

  let left = data.length;
  let str = '';
  let i = 0;

  while (left >= 3) {
    const c1 = data[i++];
    const c2 = data[i++];
    const c3 = data[i++];

    str += charset[c1 >> 2];
    str += charset[((c1 & 3) << 4) | (c2 >> 4)];
    str += charset[((c2 & 0x0f) << 2) | (c3 >> 6)];
    str += charset[c3 & 0x3f];

    left -= 3;
  }

  switch (left) {
    case 1: {
      const c1 = data[i++];

      str += charset[c1 >> 2];
      str += charset[(c1 & 3) << 4];

      if (pad)
        str += '==';

      break;
    }

    case 2: {
      const c1 = data[i++];
      const c2 = data[i++];

      str += charset[c1 >> 2];
      str += charset[((c1 & 3) << 4) | (c2 >> 4)];
      str += charset[(c2 & 0x0f) << 2];

      if (pad)
        str += '=';

      break;
    }
  }

  return str;
}

/*
 * Decoding
 */

function _decode(str, table, size) {
  assert(typeof str === 'string');

  const data = Buffer.alloc(size);

  let left = str.length;
  let i = 0;
  let j = 0;

  if (left > 0 && str[left - 1] === '=')
    left -= 1;

  if (left > 0 && str[left - 1] === '=')
    left -= 1;

  if ((left & 3) === 1) // Fail early.
    throw new Error('Invalid base64 string.');

  while (left >= 4) {
    const c1 = str.charCodeAt(i++);
    const c2 = str.charCodeAt(i++);
    const c3 = str.charCodeAt(i++);
    const c4 = str.charCodeAt(i++);

    if ((c1 | c2 | c3 | c4) & 0xff80)
      throw new Error('Invalid base64 string.');

    const t1 = table[c1];
    const t2 = table[c2];
    const t3 = table[c3];
    const t4 = table[c4];

    if ((t1 | t2 | t3 | t4) < 0)
      throw new Error('Invalid base64 string.');

    data[j++] = (t1 << 2) | (t2 >> 4);
    data[j++] = (t2 << 4) | (t3 >> 2);
    data[j++] = (t3 << 6) | (t4 >> 0);

    left -= 4;
  }

  switch (left) {
    case 1: {
      throw new Error('Invalid base64 string.');
    }

    case 2: {
      const c1 = str.charCodeAt(i++);
      const c2 = str.charCodeAt(i++);

      if ((c1 | c2) & 0xff80)
        throw new Error('Invalid base64 string.');

      const t1 = table[c1];
      const t2 = table[c2];

      if ((t1 | t2) < 0)
        throw new Error('Invalid base64 string.');

      data[j++] = (t1 << 2) | (t2 >> 4);

      if (t2 & 15)
        throw new Error('Invalid base64 string.');

      break;
    }

    case 3: {
      const c1 = str.charCodeAt(i++);
      const c2 = str.charCodeAt(i++);
      const c3 = str.charCodeAt(i++);

      if ((c1 | c2 | c3) & 0xff80)
        throw new Error('Invalid base64 string.');

      const t1 = table[c1];
      const t2 = table[c2];
      const t3 = table[c3];

      if ((t1 | t2 | t3) < 0)
        throw new Error('Invalid base64 string.');

      data[j++] = (t1 << 2) | (t2 >> 4);
      data[j++] = (t2 << 4) | (t3 >> 2);

      if (t3 & 3)
        throw new Error('Invalid base64 string.');

      break;
    }
  }

  assert(j === size);

  return data;
}

/*
 * Testing
 */

function _test(str, table) {
  assert(typeof str === 'string');

  let len = str.length;

  if (len > 0 && str[len - 1] === '=')
    len -= 1;

  if (len > 0 && str[len - 1] === '=')
    len -= 1;

  if ((len & 3) === 1)
    return false;

  for (let i = 0; i < len; i++) {
    const ch = str.charCodeAt(i);

    if (ch & 0xff80)
      return false;

    if (table[ch] === -1)
      return false;
  }

  switch (len & 3) {
    case 1:
      return false;
    case 2:
      return (table[str.charCodeAt(len - 1)] & 15) === 0;
    case 3:
      return (table[str.charCodeAt(len - 1)] & 3) === 0;
  }

  return true;
}

/*
 * Base64
 */

function encode(data) {
  return _encode(data, CHARSET, true);
}

function decode(str) {
  const size = decodeSize(str);

  if (!checkPadding(str, size))
    throw new Error('Invalid base64 padding.');

  return _decode(str, TABLE, size);
}

function test(str) {
  const size = decodeSize(str);

  if (!checkPadding(str, size))
    return false;

  return _test(str, TABLE);
}

/*
 * Base64-URL
 */

function encodeURL(data) {
  return _encode(data, CHARSET_URL, false);
}

function decodeURL(str) {
  const size = decodeSize(str);

  if (!checkPadding(str, 0))
    throw new Error('Invalid base64 padding.');

  return _decode(str, TABLE_URL, size);
}

function testURL(str) {
  if (!checkPadding(str, 0))
    return false;

  return _test(str, TABLE_URL);
}

/*
 * Helpers
 */

function decodeSize(str) {
  assert(typeof str === 'string');

  let len = str.length;

  if (len > 0 && str[len - 1] === '=')
    len -= 1;

  if (len > 0 && str[len - 1] === '=')
    len -= 1;

  let size = (len >>> 2) * 3;

  const rem = len & 3;

  if (rem)
    size += rem - 1;

  return size;
}

function checkPadding(str, size) {
  assert(typeof str === 'string');

  switch (size % 3) {
    case 0: {
      if (str.length === 0)
        return true;

      if (str.length === 1)
        return str[0] !== '=';

      return str[str.length - 2] !== '='
          && str[str.length - 1] !== '=';
    }

    case 1: {
      return str.length >= 4
          && str[str.length - 2] === '='
          && str[str.length - 1] === '=';
    }

    case 2: {
      return str.length >= 4
          && str[str.length - 2] !== '='
          && str[str.length - 1] === '=';
    }

    default: {
      throw new Error('unreachable');
    }
  }
}

/*
 * Expose
 */

exports.native = 0;
exports.encode = encode;
exports.decode = decode;
exports.test = test;
exports.encodeURL = encodeURL;
exports.decodeURL = decodeURL;
exports.testURL = testURL;
