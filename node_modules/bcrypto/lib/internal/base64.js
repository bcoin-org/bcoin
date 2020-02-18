/*!
 * base64.js - base64 for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');

/*
 * Base64
 */

function encode(buf) {
  assert(Buffer.isBuffer(buf));
  return buf.toString('base64');
}

function decode(str) {
  assert(typeof str === 'string');

  const buf = Buffer.from(str, 'base64');

  if (str.length !== size64(buf.length))
    throw new Error('Invalid base64 string.');

  return buf;
}

function encodeURL(buf) {
  assert(Buffer.isBuffer(buf));

  const raw = buf.toString('base64');
  const str = raw
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');

  return str;
}

function decodeURL(str) {
  assert(typeof str === 'string');

  const raw = pad64(str)
    .replace(/\-/g, '+')
    .replace(/_/g, '/');

  const buf = Buffer.from(raw, 'base64');

  if (raw.length !== size64(buf.length))
    throw new Error('Invalid base64-url string.');

  return buf;
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
exports.encodeURL = encodeURL;
exports.decodeURL = decodeURL;
