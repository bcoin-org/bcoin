/*!
 * random-openssl.js - random number generator for bcrypto
 * Copyright (c) 2014-2020, Christopher Jeffrey (MIT License).
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
// See: https://github.com/nodejs/node/issues/31442
const randomFillSync = crypto.randomFillSync.bind(crypto);
const pool = new Uint32Array(16);

let poolPos = 0;

/**
 * Generate pseudo-random bytes.
 * @param {Number} size
 * @returns {Buffer}
 */

function randomBytes(size) {
  assert((size >>> 0) === size);

  const data = Buffer.alloc(size);

  randomFillSync(data, 0, size);

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

  randomFillSync(data, off, size);

  return data;
}

/**
 * Generate a random uint32.
 * @returns {Number}
 */

function randomInt() {
  if ((poolPos & 15) === 0) {
    getRandomValues(pool);
    poolPos = 0;
  }

  return pool[poolPos++];
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

  let x, r;

  do {
    x = randomInt();
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
      randomFillSync(new Uint32Array(1));
      hasTypedArray = true;
    } catch (e) {
      hasTypedArray = false;
    }
  }

  if (!hasTypedArray) {
    array = Buffer.from(array.buffer,
                        array.byteOffset,
                        array.byteLength);
  }

  randomFillSync(array);
}

/*
 * Expose
 */

exports.native = 1;
exports.randomBytes = randomBytes;
exports.randomFill = randomFill;
exports.randomInt = randomInt;
exports.randomRange = randomRange;
