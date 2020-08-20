/*!
 * murmur3.js - murmur3 hash for bcrypto
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('../internal/assert');
const binding = require('./binding');

/*
 * Murmur3
 */

function sum(data, seed) {
  assert(Buffer.isBuffer(data));
  return binding.murmur3_sum(data, seed >>> 0);
}

function tweak(data, n, tweak) {
  assert(Buffer.isBuffer(data));
  return binding.murmur3_tweak(data, n >>> 0, tweak >>> 0);
}

/**
 * Expose
 */

exports.native = 2;
exports.sum = sum;
exports.tweak = tweak;
