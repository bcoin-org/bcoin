/*!
 * random.js - random number generator for bcrypto
 * Copyright (c) 2014-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://wiki.openssl.org/index.php/Random_Numbers
 *   https://csrc.nist.gov/projects/random-bit-generation/
 *   http://www.pcg-random.org/posts/bounded-rands.html
 */

'use strict';

const assert = require('../internal/assert');
const crypto = require('crypto');

/**
 * Generate pseudo-random bytes.
 * @param {Number} size
 * @returns {Buffer}
 */

function randomBytes(size) {
  assert((size >>> 0) === size);

  const data = Buffer.alloc(size, 0x00);

  crypto.randomFillSync(data, 0, size);

  return data;
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
  assert(off + size <= data.length);

  data.fill(0x00, off, off + size);

  crypto.randomFillSync(data, off, size);

  return data;
}

/**
 * Generate a random uint32.
 * @returns {Number}
 */

function randomInt() {
  const array = new Uint32Array(1);

  getRandomValues(array);

  return array[0];
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

  const space = max - min;

  if (space === 0)
    return min;

  const top = -space >>> 0;
  const array = new Uint32Array(1);

  let x, r;

  do {
    getRandomValues(array);

    x = array[0];
    r = x % space;
  } while (x - r > top);

  return r + min;
}

/*
 * Helpers
 */

let hasTypedArray = null;

function getRandomValues(array) {
  assert(array != null && typeof array === 'object');
  assert(array.buffer instanceof ArrayBuffer);

  if (hasTypedArray === null) {
    try {
      // Added in 9.0.0.
      crypto.randomFillSync(new Uint32Array(1));
      hasTypedArray = true;
    } catch (e) {
      hasTypedArray = false;
    }
  }

  array.fill(0, 0, array.length);

  if (!hasTypedArray) {
    array = Buffer.from(array.buffer,
                        array.byteOffset,
                        array.byteLength);
  }

  crypto.randomFillSync(array);
}

/*
 * Expose
 */

exports.native = 1;
exports.randomBytes = randomBytes;
exports.randomFill = randomFill;
exports.randomInt = randomInt;
exports.randomRange = randomRange;
