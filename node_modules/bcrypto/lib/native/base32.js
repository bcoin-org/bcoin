/*!
 * base32.js - base32 for bcrypto
 * Copyright (c) 2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('../internal/assert');
const binding = require('./binding');

/*
 * Base32
 */

function encode(data, pad = false) {
  assert(Buffer.isBuffer(data));
  assert(typeof pad === 'boolean');

  return binding.base32_encode(data, pad);
}

function decode(str, unpad = false) {
  assert(typeof str === 'string');
  assert(typeof unpad === 'boolean');

  return binding.base32_decode(str, unpad);
}

function test(str, unpad = false) {
  assert(typeof str === 'string');
  assert(typeof unpad === 'boolean');

  return binding.base32_test(str, unpad);
}

/*
 * Base32-Hex
 */

function encodeHex(data, pad = false) {
  assert(Buffer.isBuffer(data));
  assert(typeof pad === 'boolean');

  return binding.base32hex_encode(data, pad);
}

function decodeHex(str, unpad = false) {
  assert(typeof str === 'string');
  assert(typeof unpad === 'boolean');

  return binding.base32hex_decode(str, unpad);
}

function testHex(str, unpad = false) {
  assert(typeof str === 'string');
  assert(typeof unpad === 'boolean');

  return binding.base32hex_test(str, unpad);
}

/*
 * Expose
 */

exports.native = 2;
exports.encode = encode;
exports.decode = decode;
exports.test = test;
exports.encodeHex = encodeHex;
exports.decodeHex = decodeHex;
exports.testHex = testHex;
