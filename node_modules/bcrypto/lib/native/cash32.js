/*!
 * cash32.js - cashaddr for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('../internal/assert');
const binding = require('./binding');

/*
 * Cash32
 */

function serialize(prefix, data) {
  assert(typeof prefix === 'string');
  assert(Buffer.isBuffer(data));

  return binding.cash32_serialize(prefix, data);
}

function deserialize(str, fallback) {
  assert(typeof str === 'string');
  assert(typeof fallback === 'string');

  return binding.cash32_deserialize(str, fallback);
}

function is(str, fallback) {
  assert(typeof str === 'string');
  assert(typeof fallback === 'string');

  return binding.cash32_is(str, fallback);
}

function convertBits(data, srcbits, dstbits, pad) {
  assert(Buffer.isBuffer(data));
  assert((srcbits >>> 0) === srcbits);
  assert((dstbits >>> 0) === dstbits);
  assert(typeof pad === 'boolean');

  return binding.cash32_convert_bits(data, srcbits, dstbits, pad);
}

function encode(prefix, type, hash) {
  assert(typeof prefix === 'string');
  assert((type >>> 0) === type);
  assert(Buffer.isBuffer(hash));

  return binding.cash32_encode(prefix, type, hash);
}

function decode(addr, expect = 'bitcoincash') {
  assert(typeof addr === 'string');
  assert(typeof expect === 'string');

  return binding.cash32_decode(addr, expect);
}

function test(addr, expect = 'bitcoincash') {
  assert(typeof addr === 'string');
  assert(typeof expect === 'string');

  return binding.cash32_test(addr, expect);
}

/*
 * Expose
 */

exports.native = 2;
exports.serialize = serialize;
exports.deserialize = deserialize;
exports.is = is;
exports.convertBits = convertBits;
exports.encode = encode;
exports.decode = decode;
exports.test = test;
