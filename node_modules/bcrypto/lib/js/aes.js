/*!
 * aes.js - aes128/192/256 for bcrypto
 * Copyright (c) 2016-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const AES = require('./ciphers/aes');
const {CBCCipher, CBCDecipher} = require('./ciphers/modes');

/**
 * Encrypt data with aes 256 cbc.
 * @param {Buffer} data
 * @param {Buffer} key
 * @param {Buffer} iv
 * @returns {Buffer}
 */

function encipher(data, key, iv) {
  const ctx = new CBCCipher(new AES(256));
  ctx.init(key, iv);
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
  const ctx = new CBCDecipher(new AES(256));
  ctx.init(key, iv);
  return Buffer.concat([ctx.update(data), ctx.final()]);
}

/*
 * Expose
 */

exports.native = 0;
exports.encipher = encipher;
exports.decipher = decipher;
