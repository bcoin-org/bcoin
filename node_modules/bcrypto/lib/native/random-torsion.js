/*!
 * random-torsion.js - random number generator for bcrypto
 * Copyright (c) 2014-2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('../internal/assert');
const binding = require('loady')('bcrypto', __dirname);

/**
 * Generate pseudo-random bytes.
 * @param {Number} size
 * @returns {Buffer}
 */

function randomBytes(size) {
  assert((size >>> 0) === size);

  const data = Buffer.alloc(size);

  return binding.getrandom(data, 0, size);
}

/**
 * Generate pseudo-random bytes.
 * @param {Buffer} data
 * @param {Number} [off=0]
 * @param {Number} [size=data.length-off]
 * @returns {Buffer}
 */

function randomFill(data, off, size) {
  assert(Buffer.isBuffer(data));

  if (off == null)
    off = 0;

  assert((off >>> 0) === off);

  if (size == null)
    size = data.length - off;

  assert((size >>> 0) === size);

  return binding.getrandom(data, off, size);
}

/**
 * Generate a random uint32.
 * @returns {Number}
 */

function randomInt() {
  return binding.random();
}

/**
 * Generate a random uint32 within a range.
 * @param {Number} min - Inclusive.
 * @param {Number} max - Exclusive.
 * @returns {Number}
 */

function randomRange(min, max) {
  assert((min >>> 0) === min);
  assert((max >>> 0) === max);
  assert(max >= min);

  return min + binding.uniform(max - min);
}

/**
 * Get OS entropy (for testing).
 * @private
 * @param {Number} size
 * @returns {Buffer}
 */

function getEntropy(size) {
  assert((size >>> 0) === size);

  const data = Buffer.alloc(size);

  return binding.getentropy(data, 0, size);
}

/*
 * Expose
 */

exports.native = 2;
exports.randomBytes = randomBytes;
exports.randomFill = randomFill;
exports.randomInt = randomInt;
exports.randomRange = randomRange;
exports._getEntropy = getEntropy;
