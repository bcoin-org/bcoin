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

  const items = binding.siphash(data, key);

  items[0] |= 0;
  items[1] |= 0;

  return items;
}

function siphash32(num, key) {
  assert(Buffer.isBuffer(key));
  return binding.siphash32(num >>> 0, key) | 0;
}

function siphash64(hi, lo, key) {
  assert(Buffer.isBuffer(key));

  const items = binding.siphash64(hi >>> 0, lo >>> 0, key);

  items[0] |= 0;
  items[1] |= 0;

  return items;
}

function siphash32k256(num, key) {
  assert(Buffer.isBuffer(key));
  return binding.siphash32k256(num >>> 0, key) | 0;
}

function siphash64k256(hi, lo, key) {
  assert(Buffer.isBuffer(key));

  const items = binding.siphash64k256(hi >>> 0, lo >>> 0, key);

  items[0] |= 0;
  items[1] |= 0;

  return items;
}

function sipmod(data, key, mhi, mlo) {
  assert(Buffer.isBuffer(data));
  assert(Buffer.isBuffer(key));

  const items = binding.sipmod(data, key, mhi >>> 0, mlo >>> 0);

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
