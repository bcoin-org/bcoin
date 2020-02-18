/*!
 * random.js - randomness for bcrypto
 * Copyright (c) 2014-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');

/**
 * Whether the backend is a binding.
 * @const {Number}
 */

exports.native = 0;

/**
 * Generate pseudo-random bytes.
 * @param {Number} size
 * @returns {Buffer}
 */

exports.randomBytes = function randomBytes(size) {
  assert((size >>> 0) === size);

  const data = Buffer.alloc(size);

  exports.randomFill(data, 0, data.length);

  return data;
};

/**
 * Generate pseudo-random bytes.
 * @param {Buffer} buf
 * @param {Number} [off=0]
 * @param {Number} [size=buf.length-off]
 * @returns {Buffer}
 */

exports.randomFill = function randomFill(buf, off, size) {
  assert(Buffer.isBuffer(buf));
  assert(buf.buffer instanceof ArrayBuffer);
  assert((buf.byteOffset >>> 0) === buf.byteOffset);

  if (off == null)
    off = 0;

  assert((off >>> 0) === off);

  if (size == null)
    size = buf.length - off;

  assert((size >>> 0) === size);
  assert(off + size <= buf.length);

  const data = new Uint8Array(
    buf.buffer,
    buf.byteOffset + off,
    size
  );

  getRandomValues(data);

  return buf;
};

/**
 * Generate pseudo-random bytes.
 * @param {Number} size
 * @returns {Promise}
 */

exports.randomBytesAsync = async function randomBytesAsync(size) {
  return exports.randomBytes(size);
};

/**
 * Generate pseudo-random bytes.
 * @param {Buffer} buf
 * @param {Number} [off=0]
 * @param {Number} [size=buf.length-size]
 * @returns {Promise}
 */

exports.randomFillAsync = async function randomFillAsync(buf, off, size) {
  return exports.randomFill(buf, off, size);
};

/**
 * Generate a random uint32.
 * Probably more cryptographically sound than
 * `Math.random()`.
 * @returns {Number}
 */

exports.randomInt = function randomInt() {
  return exports.randomBytes(4).readUInt32LE(0);
};

/**
 * Generate a random number within a range.
 * Probably more cryptographically sound than
 * `Math.random()`.
 * @param {Number} min - Inclusive.
 * @param {Number} max - Exclusive.
 * @returns {Number}
 */

exports.randomRange = function randomRange(min, max) {
  assert((min >>> 0) === min);
  assert((max >>> 0) === max);
  assert(max >= min);
  const num = exports.randomInt();
  return Math.floor((num / 0x100000000) * (max - min) + min);
};

/*
 * Helpers
 */

function isTesting() {
  return typeof process === 'object'
      && process
      && process.env
      && process.env.NODE_TEST === '1'
      && !process.browser;
}

function getRandomValues(array) {
  assert(array instanceof Uint8Array);

  if (array.length > (2 ** 31 - 1))
    throw new RangeError('The value "size" is out of range.');

  const crypto = global.crypto || global.msCrypto;

  // Native WebCrypto support.
  // https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues
  if (crypto && typeof crypto.getRandomValues === 'function') {
    const max = 65536;

    if (array.length > max) {
      for (let i = 0; i < array.length; i += max) {
        let j = i + max;

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
  if (isTesting()) {
    for (let i = 0; i < array.length; i++)
      array[i] = Math.floor(Math.random() * 256);
    return;
  }

  // Error if no randomness is available.
  // We don't want people using bad randomness
  // when keys are at stake!
  throw new Error('Entropy source not available.');
}
