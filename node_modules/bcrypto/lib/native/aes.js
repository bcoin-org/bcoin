/*!
 * aes.js - aes for bcrypto
 * Copyright (c) 2014-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('../internal/assert');
const binding = require('./binding');

/*
 * Constants
 */

const type = binding.ciphers.AES256;
const mode = binding.modes.CBC;

/**
 * Encrypt data with aes 256 cbc.
 * @param {Buffer} data
 * @param {Buffer} key
 * @param {Buffer} iv
 * @returns {Buffer}
 */

function encipher(data, key, iv) {
  assert(Buffer.isBuffer(data));
  assert(Buffer.isBuffer(key));
  assert(Buffer.isBuffer(iv));

  const {buffer, length} = binding.cipher_encrypt(type, mode, key, iv, data);

  return Buffer.from(buffer, 0, length);
}

/**
 * Decrypt data with aes 256 cbc.
 * @param {Buffer} data
 * @param {Buffer} key
 * @param {Buffer} iv
 * @returns {Buffer}
 */

function decipher(data, key, iv) {
  assert(Buffer.isBuffer(data));
  assert(Buffer.isBuffer(key));
  assert(Buffer.isBuffer(iv));

  const {buffer, length} = binding.cipher_decrypt(type, mode, key, iv, data);

  return Buffer.from(buffer, 0, length);
}

/*
 * Expose
 */

exports.native = 2;
exports.encipher = encipher;
exports.decipher = decipher;
