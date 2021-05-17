/*!
 * base16.js - base16 for javascript
 * Copyright (c) 2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('../internal/assert');
const binding = require('./binding');

/*
 * Base16
 */

function encode(data) {
  assert(Buffer.isBuffer(data));
  return binding.base16_encode(data);
}

function decode(str) {
  assert(typeof str === 'string');
  return binding.base16_decode(str);
}

function test(str) {
  assert(typeof str === 'string');
  return binding.base16_test(str);
}

/*
 * Base16 (Little Endian)
 */

function encodeLE(data) {
  assert(Buffer.isBuffer(data));
  return binding.base16le_encode(data);
}

function decodeLE(str) {
  assert(typeof str === 'string');
  return binding.base16le_decode(str);
}

function testLE(str) {
  assert(typeof str === 'string');
  return binding.base16le_test(str);
}

/*
 * Expose
 */

exports.native = 2;
exports.encode = encode;
exports.decode = decode;
exports.test = test;
exports.encodeLE = encodeLE;
exports.decodeLE = decodeLE;
exports.testLE = testLE;
