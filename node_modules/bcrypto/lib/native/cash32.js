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

function deserialize(str, defaultPrefix) {
  assert(typeof str === 'string');
  assert(typeof defaultPrefix === 'string');

  return binding.cash32_deserialize(str, defaultPrefix);
}

function is(str, defaultPrefix) {
  assert(typeof str === 'string');
  assert(typeof defaultPrefix === 'string');

  return binding.cash32_is(str, defaultPrefix);
}

function convertBits(data, frombits, tobits, pad) {
  assert(Buffer.isBuffer(data));
  assert((frombits >>> 0) === frombits);
  assert((tobits >>> 0) === tobits);
  assert(typeof pad === 'boolean');

  return binding.cash32_convert_bits(data, frombits, tobits, pad);
}

function encode(prefix, type, hash) {
  assert(typeof prefix === 'string');
  assert((type >>> 0) === type);
  assert(Buffer.isBuffer(hash));

  return binding.cash32_encode(prefix, type, hash);
}

function decode(str, defaultPrefix = 'bitcoincash') {
  assert(typeof str === 'string');
  assert(typeof defaultPrefix === 'string');

  return binding.cash32_decode(str, defaultPrefix);
}

function test(str, defaultPrefix = 'bitcoincash') {
  assert(typeof str === 'string');
  assert(typeof defaultPrefix === 'string');

  return binding.cash32_test(str, defaultPrefix);
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
