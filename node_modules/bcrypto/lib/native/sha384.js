/*!
 * sha384.js - SHA384 implementation for bcrypto
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const {SHA384} = require('./binding');
const HMAC = require('../internal/hmac');

SHA384.hash = function hash() {
  return new SHA384();
};

SHA384.hmac = function hmac() {
  return new HMAC(SHA384, 128);
};

SHA384.mac = function mac(data, key) {
  return SHA384.hmac().init(key).update(data).final();
};

SHA384.native = 2;
SHA384.id = 'SHA384';
SHA384.size = 48;
SHA384.bits = 384;
SHA384.blockSize = 128;
SHA384.zero = Buffer.alloc(48, 0x00);
SHA384.ctx = new SHA384();

module.exports = SHA384;
