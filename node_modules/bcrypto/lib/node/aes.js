/*!
 * aes.js - aes for bcrypto
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
 * Encrypt data with aes 256 cbc.
 * @param {Buffer} data
 * @param {Buffer} key
 * @param {Buffer} iv
 * @returns {Buffer}
 */

exports.encipher = function encipher(data, key, iv) {
  assert(Buffer.isBuffer(data));
  assert(Buffer.isBuffer(key));
  assert(Buffer.isBuffer(iv));

  const ctx = crypto.createCipheriv('AES-256-CBC', key, iv);

  return Buffer.concat([ctx.update(data), ctx.final()]);
};

/**
 * Decrypt data with aes 256 cbc.
 * @param {Buffer} data
 * @param {Buffer} key
 * @param {Buffer} iv
 * @returns {Buffer}
 */

exports.decipher = function decipher(data, key, iv) {
  assert(Buffer.isBuffer(data));
  assert(Buffer.isBuffer(key));
  assert(Buffer.isBuffer(iv));

  const ctx = crypto.createDecipheriv('AES-256-CBC', key, iv);

  try {
    return Buffer.concat([ctx.update(data), ctx.final()]);
  } catch (e) {
    throw new Error('Bad key for decryption.');
  }
};
