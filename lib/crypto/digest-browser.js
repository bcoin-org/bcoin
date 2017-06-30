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
const sha256 = require('./sha256');

/**
 * Hash with chosen algorithm.
 * @param {String} alg
 * @param {Buffer} data
 * @returns {Buffer}
 */

exports.hash = function _hash(alg, data) {
  let hash;

  if (alg === 'sha256')
    return sha256.digest(data);

  hash = hashjs[alg];

  assert(hash != null, 'Unknown algorithm.');

  return Buffer.from(hash().update(data).digest());
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

exports.sha256 = function _sha256(data) {
  return sha256.digest(data);
};

/**
 * Hash with sha256 and ripemd160 (OP_HASH160).
 * @param {Buffer} data
 * @returns {Buffer}
 */

exports.hash160 = function hash160(data) {
  return exports.hash('ripemd160', sha256.digest(data));
};

/**
 * Hash with sha256 twice (OP_HASH256).
 * @param {Buffer} data
 * @returns {Buffer}
 */

exports.hash256 = function hash256(data) {
  return sha256.hash256(data);
};

/**
 * Create an HMAC.
 * @param {String} alg
 * @param {Buffer} data
 * @param {Buffer} key
 * @returns {Buffer} HMAC
 */

exports.hmac = function _hmac(alg, data, key) {
  let hash = hashjs[alg];
  let hmac;

  assert(hash != null, 'Unknown algorithm.');

  hmac = hashjs.hmac(hash, key);

  return Buffer.from(hmac.update(data).digest());
};
