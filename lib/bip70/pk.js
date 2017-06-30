/*!
 * pk.js - public key algorithms for bcoin
 * Copyright (c) 2016-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/**
 * @module bip70/pk
 */

const rsa = require('../crypto/rsa');
const ecdsa = require('../crypto/ecdsa');

/**
 * Verify signature with public key.
 * @param {String} hash - Hash algorithm.
 * @param {Buffer} msg
 * @param {Buffer} sig
 * @param {Object} key
 * @returns {Boolean}
 */

exports.verify = function verify(hash, msg, sig, key) {
  switch (key.alg) {
    case 'rsa':
      return rsa.verify(hash, msg, sig, key.data);
    case 'ecdsa':
      return ecdsa.verify(key.curve, hash, msg, sig, key.data);
    default:
      throw new Error('Unsupported algorithm.');
  }
};

/**
 * Sign message with private key.
 * @param {String} hash - Hash algorithm.
 * @param {Buffer} msg
 * @param {Object} key
 * @returns {Buffer}
 */

exports.sign = function sign(hash, msg, key) {
  switch (key.alg) {
    case 'rsa':
      return rsa.sign(hash, msg, key.data);
    case 'ecdsa':
      return ecdsa.sign(key.curve, hash, msg, key.data);
    default:
      throw new Error('Unsupported algorithm.');
  }
};
