/*!
 * random.js - randomness for bcrypto
 * Copyright (c) 2014-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const crypto = require('crypto');

/**
 * Whether the backend is a binding.
 * @const {Number}
 */

exports.native = 1;

/**
 * Generate pseudo-random bytes.
 * @function
 * @param {Number} size
 * @returns {Buffer}
 */

exports.randomBytes = function randomBytes(size) {
  return crypto.randomBytes(size);
};

/**
 * Generate pseudo-random bytes.
 * @param {Buffer} buf
 * @param {Number} [off=0]
 * @param {Number} [size=buf.length-off]
 * @returns {Buffer}
 */

exports.randomFill = crypto.randomFillSync;

/**
 * Generate pseudo-random bytes.
 * @param {Number} size
 * @returns {Promise}
 */

exports.randomBytesAsync = function randomBytesAsync(size) {
  return new Promise((resolve, reject) => {
    const cb = (err, result) => {
      if (err) {
        reject(err);
        return;
      }
      resolve(result);
    };

    try {
      crypto.randomBytes(size, cb);
    } catch (e) {
      reject(e);
    }
  });
};

/**
 * Generate pseudo-random bytes.
 * @param {Buffer} buf
 * @param {Number} [off=0]
 * @param {Number} [size=buf.length-size]
 * @returns {Promise}
 */

exports.randomFillAsync = function randomFillAsync(...args) {
  return new Promise((resolve, reject) => {
    const cb = (err, result) => {
      if (err) {
        reject(err);
        return;
      }
      resolve(result);
    };

    args.push(cb);

    try {
      crypto.randomFill(...args);
    } catch (e) {
      reject(e);
    }
  });
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
