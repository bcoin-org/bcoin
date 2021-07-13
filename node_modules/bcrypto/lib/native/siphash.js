/*!
 * siphash.js - siphash for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('../internal/assert');
const binding = require('./binding');

/*
 * Siphash
 */

function siphash(data, key) {
  assert(Buffer.isBuffer(data));
  assert(Buffer.isBuffer(key));

  const items = binding.siphash_sum(data, key);

  items[0] |= 0;
  items[1] |= 0;

  return items;
}

function siphash32(num, key) {
  return siphash64(0, num, key)[1];
}

function siphash64(hi, lo, key) {
  assert(Buffer.isBuffer(key));

  const items = binding.siphash128_sum(hi >>> 0, lo >>> 0, key);

  items[0] |= 0;
  items[1] |= 0;

  return items;
}

function siphash32k256(num, key) {
  return siphash64k256(0, num, key)[1];
}

function siphash64k256(hi, lo, key) {
  assert(Buffer.isBuffer(key));

  const items = binding.siphash256_sum(hi >>> 0, lo >>> 0, key);

  items[0] |= 0;
  items[1] |= 0;

  return items;
}

function sipmod(data, key, mhi, mlo) {
  assert(Buffer.isBuffer(data));
  assert(Buffer.isBuffer(key));

  const items = binding.siphash_mod(data, key, mhi >>> 0, mlo >>> 0);

  items[0] |= 0;
  items[1] |= 0;

  return items;
}

/*
 * Expose
 */

exports.native = 2;
exports.siphash = siphash;
exports.siphash32 = siphash32;
exports.siphash64 = siphash64;
exports.siphash32k256 = siphash32k256;
exports.siphash64k256 = siphash64k256;
exports.sipmod = sipmod;
