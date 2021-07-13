/*!
 * base64.js - base64 for javascript
 * Copyright (c) 2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://tools.ietf.org/html/rfc4648
 */

'use strict';

const assert = require('../internal/assert');

/*
 * Base64
 */

function encode(data) {
  assert(Buffer.isBuffer(data));
  return data.toString('base64');
}

function decode(str) {
  assert(typeof str === 'string');

  if (/[\-_]/.test(str))
    throw new Error('Invalid base64 string.');

  const data = Buffer.from(str, 'base64');

  if (str.length !== size64(data.length))
    throw new Error('Invalid base64 string.');

  return data;
}

function test(str) {
  assert(typeof str === 'string');

  // The only way to get an accurate string
  // size for base64 is by allocating a buffer.
  // Note that browserify _does_ allocate a
  // buffer to calculate base64 decoded size.
  //
  // https://github.com/nodejs/node/blob/524dd4/lib/buffer.js#L477
  // https://github.com/nodejs/node/blob/524dd4/src/node_buffer.cc#L250
  // https://github.com/nodejs/node/blob/524dd4/src/string_bytes.cc#L457
  // https://github.com/feross/buffer/blob/b651e3a/index.js#L415
  try {
    decode(str);
    return true;
  } catch (e) {
    return false;
  }
}

function encodeURL(data) {
  const raw = encode(data);

  const str = raw
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');

  return str;
}

function decodeURL(str) {
  assert(typeof str === 'string');

  if (/[=\+\/]/.test(str))
    throw new Error('Invalid base64-url string.');

  const raw = pad64(str)
    .replace(/\-/g, '+')
    .replace(/_/g, '/');

  return decode(raw);
}

function testURL(str) {
  assert(typeof str === 'string');

  try {
    decodeURL(str);
    return true;
  } catch (e) {
    return false;
  }
}

/*
 * Helpers
 */

function pad64(str) {
  switch (str.length & 3) {
    case 2:
      str += '==';
      break;
    case 3:
      str += '=';
      break;
  }
  return str;
}

function size64(size) {
  const expect = ((4 * size / 3) + 3) & ~3;
  return expect >>> 0;
}

/*
 * Expose
 */

exports.encode = encode;
exports.decode = decode;
exports.test = test;
exports.encodeURL = encodeURL;
exports.decodeURL = decodeURL;
exports.testURL = testURL;
