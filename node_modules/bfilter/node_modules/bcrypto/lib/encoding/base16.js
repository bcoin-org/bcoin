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
const isBrowser = Buffer.alloc(0)._isBuffer === true;

/*
 * Base16
 */

function encode(data, size) {
  assert(Buffer.isBuffer(data));
  assert(size == null || (size >>> 0) === size);

  let str = data.toString('hex');

  if (size != null) {
    size *= 2;

    if (str.length > size)
      throw new RangeError('Data length exceeds requested size.');

    while (str.length < size)
      str = '00' + str;
  }

  return str;
}

function encodeLE(data, size) {
  const str = encode(data, size);

  let out = '';

  for (let i = str.length - 2; i >= 0; i -= 2)
    out += str[i] + str[i + 1];

  return out;
}

function decode(str, size) {
  assert(typeof str === 'string');
  assert(size == null || (size >>> 0) === size);

  if (str.length & 1)
    throw new Error('Invalid hex string.');

  if (size != null && str.length !== size * 2)
    throw new RangeError('String length differs from expected size.');

  const data = Buffer.from(str, 'hex');

  if (str.length !== data.length * 2)
    throw new Error('Invalid hex string.');

  if (isBrowser && data.length > 0) {
    // Browserify may parse hex as:
    //
    //   parseInt(str.substring(i, i + 2), 16)
    //
    // This causes problems with error cases.
    //
    // For example:
    //
    //   parseInt('6x', 16) === 6
    //
    // This means our final byte with an
    // invalid character will be `06` and
    // it does not affect the length of
    // the buffer. We can check for this
    // below.
    //
    // This differs from node. Node will
    // discard the entire byte regardless
    // of which character is invalid.
    //
    // https://github.com/nodejs/node/blob/524dd46/src/string_bytes.cc#L247
    // https://github.com/feross/buffer/blob/b651e3a/index.js#L806
    if ((data[data.length - 1] >>> 4) === 0) {
      if (!/[0-9a-f]$/i.test(str))
        throw new Error('Invalid hex string.');
    }
  }

  return data;
}

function decodeLE(str, size) {
  const data = decode(str, size);

  for (let i = data.length - 1, j = 0; i > j; i--, j++)
    [data[i], data[j]] = [data[j], data[i]];

  return data;
}

function test(str, size) {
  assert(typeof str === 'string');
  assert(size == null || (size >>> 0) === size);

  // Note: We cannot use byteLength to validate since the
  // calculation is a simple division by 2 without parsing.
  //
  // https://github.com/nodejs/node/blob/524dd46/lib/buffer.js#L540
  // https://github.com/feross/buffer/blob/b651e3a/index.js#L415
  if (str.length & 1)
    return false;

  if (size != null && str.length !== size * 2)
    return false;

  return /^[0-9a-f]*$/i.test(str);
}

/*
 * Expose
 */

exports.encode = encode;
exports.encodeLE = encodeLE;
exports.decode = decode;
exports.decodeLE = decodeLE;
exports.test = test;
