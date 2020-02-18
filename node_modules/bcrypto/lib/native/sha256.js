/*!
 * sha256.js - SHA256 implementation for bcrypto
 * Copyright (c) 2016-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const {SHA256} = require('./binding');
const HMAC = require('../internal/hmac');

SHA256.hash = function hash() {
  return new SHA256();
};

SHA256.hmac = function hmac() {
  return new HMAC(SHA256, 64);
};

SHA256.mac = function mac(data, key) {
  return SHA256.hmac().init(key).update(data).final();
};

SHA256.native = 2;
SHA256.id = 'SHA256';
SHA256.size = 32;
SHA256.bits = 256;
SHA256.blockSize = 64;
SHA256.zero = Buffer.alloc(32, 0x00);
SHA256.ctx = new SHA256();

module.exports = SHA256;
