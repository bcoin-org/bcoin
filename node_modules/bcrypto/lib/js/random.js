/*!
 * random.js - random number generator for bcrypto
 * Copyright (c) 2014-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://wiki.openssl.org/index.php/Random_Numbers
 *   https://csrc.nist.gov/projects/random-bit-generation/
 *   http://www.pcg-random.org/posts/bounded-rands.html
 *   https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues
 */

'use strict';

const assert = require('../internal/assert');

/*
 * Constants
 */

const crypto = global.crypto || global.msCrypto;
const HAS_CRYPTO = crypto && typeof crypto.getRandomValues === 'function';
const MAX_BYTES = 65536;

/**
 * Generate pseudo-random bytes.
 * @param {Number} size
 * @returns {Buffer}
 */

function randomBytes(size) {
  assert((size >>> 0) === size);

  const data = Buffer.allocUnsafeSlow(size);

  getRandomValues(data);

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

  getRandomValues(data.slice(off, off + size));

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

function getRandomValues(data) {
  assert(data != null && typeof data === 'object');
  assert(data.buffer instanceof ArrayBuffer);
  assert((data.byteOffset >>> 0) === data.byteOffset);
  assert((data.byteLength >>> 0) === data.byteLength);

  if (data.byteLength > 2 ** 31 - 1)
    throw new RangeError('The value "size" is out of range.');

  const array = new Uint8Array(data.buffer,
                               data.byteOffset,
                               data.byteLength);

  // Zero to make RNG failures more detectable.
  if (typeof array.fill === 'function') {
    array.fill(0x00, 0, array.length);
  } else {
    for (let i = 0; i < array.length; i++)
      array[i] = 0x00;
  }

  // Native WebCrypto support.
  if (HAS_CRYPTO) {
    if (array.length > MAX_BYTES) {
      for (let i = 0; i < array.length; i += MAX_BYTES) {
        let j = i + MAX_BYTES;

        if (j > array.length)
          j = array.length;

        crypto.getRandomValues(array.subarray(i, j));
      }
    } else {
      if (array.length > 0)
        crypto.getRandomValues(array);
    }

    return;
  }

  // Fallback to Math.random (FOR TESTING ONLY).
  if (!process.browser && process.env.NODE_TEST === '1') {
    for (let i = 0; i < array.length; i++)
      array[i] = Math.floor(Math.random() * 0x100);

    return;
  }

  // Error if no randomness is available.
  throw new Error('Entropy source not available.');
}

/*
 * Expose
 */

exports.native = 0;
exports.randomBytes = randomBytes;
exports.randomFill = randomFill;
exports.randomInt = randomInt;
exports.randomRange = randomRange;
