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
const randomValues = HAS_CRYPTO ? crypto.getRandomValues.bind(crypto) : null;
const pool = new Uint32Array(16);
const MAX_BYTES = 65536;

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

function getRandomValues(array) {
  if (!HAS_CRYPTO)
    throw new Error('Entropy source not available.');

  return randomValues(array);
}

function randomFillSync(data, off, size) {
  assert(Buffer.isBuffer(data));
  assert(data.buffer instanceof ArrayBuffer);
  assert((data.byteOffset >>> 0) === data.byteOffset);
  assert((data.byteLength >>> 0) === data.byteLength);
  assert((off >>> 0) === off);
  assert((size >>> 0) === size);
  assert(off + size <= data.byteLength);

  if (size > 2 ** 31 - 1)
    throw new RangeError('The value "size" is out of range.');

  const offset = data.byteOffset + off;
  const array = new Uint8Array(data.buffer, offset, size);

  if (array.length > MAX_BYTES) {
    for (let i = 0; i < array.length; i += MAX_BYTES) {
      let j = i + MAX_BYTES;

      if (j > array.length)
        j = array.length;

      getRandomValues(array.subarray(i, j));
    }
  } else {
    if (array.length > 0)
      getRandomValues(array);
  }
}

/*
 * Expose
 */

exports.native = 0;
exports.randomBytes = randomBytes;
exports.randomFill = randomFill;
exports.randomInt = randomInt;
exports.randomRange = randomRange;
