/*!
 * aes.js - aes for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/**
 * @module crypto.aes
 */

var crypto = require('crypto');
var util = require('../utils/util');
var native = require('../native').binding;

/**
 * Encrypt data with aes 256 cbc.
 * @param {Buffer} data
 * @param {Buffer} key
 * @param {Buffer} iv
 * @returns {Buffer}
 */

exports.encipher = function encipher(data, key, iv) {
  var cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  return util.concat(cipher.update(data), cipher.final());
};

/**
 * Decrypt data with aes 256 cbc.
 * @param {Buffer} data
 * @param {Buffer} key
 * @param {Buffer} iv
 * @returns {Buffer}
 */

exports.decipher = function decipher(data, key, iv) {
  var decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  try {
    return util.concat(decipher.update(data), decipher.final());
  } catch (e) {
    throw new Error('Bad key for decryption.');
  }
};

if (native) {
  exports.encipher = native.encipher;
  exports.decipher = native.decipher;
}
