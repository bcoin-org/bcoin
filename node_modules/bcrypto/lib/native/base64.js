/*!
 * base64.js - base64 for javascript
 * Copyright (c) 2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('../internal/assert');
const binding = require('./binding');

/*
 * Base64
 */

function encode(data) {
  assert(Buffer.isBuffer(data));
  return binding.base64_encode(data);
}

function decode(str) {
  assert(typeof str === 'string');
  return binding.base64_decode(str);
}

function test(str) {
  assert(typeof str === 'string');
  return binding.base64_test(str);
}

/*
 * Base64-URL
 */

function encodeURL(data) {
  assert(Buffer.isBuffer(data));
  return binding.base64url_encode(data);
}

function decodeURL(str) {
  assert(typeof str === 'string');
  return binding.base64url_decode(str);
}

function testURL(str) {
  assert(typeof str === 'string');
  return binding.base64url_test(str);
}

/*
 * Expose
 */

exports.native = 2;
exports.encode = encode;
exports.decode = decode;
exports.test = test;
exports.encodeURL = encodeURL;
exports.decodeURL = decodeURL;
exports.testURL = testURL;
