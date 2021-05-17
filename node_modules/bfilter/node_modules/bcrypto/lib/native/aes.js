/*!
 * aes.js - aes for bcrypto
 * Copyright (c) 2014-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('../internal/assert');
const crypto = require('crypto');

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

  const ctx = crypto.createCipheriv('AES-256-CBC', key, iv);

  return Buffer.concat([ctx.update(data), ctx.final()]);
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

  const ctx = crypto.createDecipheriv('AES-256-CBC', key, iv);

  try {
    return Buffer.concat([ctx.update(data), ctx.final()]);
  } catch (e) {
    throw new Error('Bad key for decryption.');
  }
}

/*
 * Expose
 */

exports.native = 1;
exports.encipher = encipher;
exports.decipher = decipher;
