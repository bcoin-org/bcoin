/*!
 * aes.js - aes128/192/256 for bcrypto
 * Copyright (c) 2016-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const AES = require('./ciphers/aes');
const {CBCCipher, CBCDecipher} = require('./ciphers/modes');

/**
 * Whether the backend is a binding.
 * @const {Number}
 */

exports.native = 0;

/**
 * Encrypt data with aes 256 cbc.
 * @param {Buffer} data
 * @param {Buffer} key
 * @param {Buffer} iv
 * @returns {Buffer}
 */

exports.encipher = function encipher(data, key, iv) {
  const ctx = new CBCCipher(new AES(256));
  ctx.init(key, iv);
  return concat(ctx.update(data), ctx.final());
};

/**
 * Decrypt data with aes 256 cbc.
 * @param {Buffer} data
 * @param {Buffer} key
 * @param {Buffer} iv
 * @returns {Buffer}
 */

exports.decipher = function decipher(data, key, iv) {
  const ctx = new CBCDecipher(new AES(256));
  ctx.init(key, iv);
  return concat(ctx.update(data), ctx.final());
};

/*
 * Helpers
 */

function concat(a, b) {
  const data = Buffer.allocUnsafe(a.length + b.length);
  a.copy(data, 0);
  b.copy(data, a.length);
  return data;
}
