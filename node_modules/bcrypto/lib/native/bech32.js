/*!
 * bech32.js - bech32 for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('../internal/assert');
const binding = require('./binding');

/*
 * Bech32
 */

function serialize(hrp, data) {
  assert(typeof hrp === 'string');
  assert(Buffer.isBuffer(data));

  return binding.bech32_serialize(hrp, data);
}

function deserialize(str) {
  assert(typeof str === 'string');
  return binding.bech32_deserialize(str);
}

function is(str) {
  assert(typeof str === 'string');
  return binding.bech32_is(str);
}

function convertBits(data, srcbits, dstbits, pad) {
  assert(Buffer.isBuffer(data));
  assert((srcbits >>> 0) === srcbits);
  assert((dstbits >>> 0) === dstbits);
  assert(typeof pad === 'boolean');

  return binding.bech32_convert_bits(data, srcbits, dstbits, pad);
}

function encode(hrp, version, hash) {
  assert(typeof hrp === 'string');
  assert((version >>> 0) === version);
  assert(Buffer.isBuffer(hash));

  return binding.bech32_encode(hrp, version, hash);
}

function decode(addr) {
  assert(typeof addr === 'string');
  return binding.bech32_decode(addr);
}

function test(addr) {
  assert(typeof addr === 'string');
  return binding.bech32_test(addr);
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
