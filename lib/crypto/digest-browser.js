/*!
 * digest-browser.js - hash functions for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/**
 * @module crypto.digest-browser
 * @ignore
 */

const assert = require('assert');
const hashjs = require('hash.js');
const SHA256 = require('./sha256');
const POOL64 = Buffer.allocUnsafe(64);

/**
 * Hash with chosen algorithm.
 * @param {String} alg
 * @param {Buffer} data
 * @returns {Buffer}
 */

exports.hash = function hash(alg, data) {
  if (alg === 'sha256')
    return SHA256.digest(data);

  const algo = hashjs[alg];

  assert(algo != null, 'Unknown algorithm.');

  return Buffer.from(algo().update(data).digest());
};

/**
 * Hash with ripemd160.
 * @param {Buffer} data
 * @returns {Buffer}
 */

exports.ripemd160 = function ripemd160(data) {
  return exports.hash('ripemd160', data);
};

/**
 * Hash with sha1.
 * @param {Buffer} data
 * @returns {Buffer}
 */

exports.sha1 = function sha1(data) {
  return exports.hash('sha1', data);
};

/**
 * Hash with sha256.
 * @param {Buffer} data
 * @returns {Buffer}
 */

exports.sha256 = function sha256(data) {
  return SHA256.digest(data);
};

/**
 * Hash with sha256 and ripemd160 (OP_HASH160).
 * @param {Buffer} data
 * @returns {Buffer}
 */

exports.hash160 = function hash160(data) {
  return exports.hash('ripemd160', SHA256.digest(data));
};

/**
 * Hash with sha256 twice (OP_HASH256).
 * @param {Buffer} data
 * @returns {Buffer}
 */

exports.hash256 = function hash256(data) {
  return SHA256.hash256(data);
};

/**
 * Hash left and right hashes with hash256.
 * @param {Buffer} left
 * @param {Buffer} right
 * @returns {Buffer}
 */

exports.root256 = function root256(left, right) {
  const data = POOL64;

  assert(left.length === 32);
  assert(right.length === 32);

  left.copy(data, 0);
  right.copy(data, 32);

  return exports.hash256(data);
};

/**
 * Create an HMAC.
 * @param {String} alg
 * @param {Buffer} data
 * @param {Buffer} key
 * @returns {Buffer} HMAC
 */

exports.hmac = function hmac(alg, data, key) {
  const algo = hashjs[alg];

  assert(algo != null, 'Unknown algorithm.');

  const ctx = hashjs.hmac(algo, key);

  return Buffer.from(ctx.update(data).digest());
};
