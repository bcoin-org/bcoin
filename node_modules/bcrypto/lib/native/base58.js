/*!
 * base58.js - base58 for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('../internal/assert');
const binding = require('./binding');

/*
 * Base58
 */

function encode(data) {
  assert(Buffer.isBuffer(data));
  return binding.base58_encode(data);
}

function decode(str) {
  assert(typeof str === 'string');

  const {buffer, length} = binding.base58_decode(str);

  return Buffer.from(buffer, 0, length);
}

function test(str) {
  assert(typeof str === 'string');
  return binding.base58_test(str);
}

/*
 * Expose
 */

exports.native = 2;
exports.encode = encode;
exports.decode = decode;
exports.test = test;
