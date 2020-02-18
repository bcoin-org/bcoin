/*!
 * md4.js - md4 for bcrypto
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const {MD4} = require('./binding');
const HMAC = require('../internal/hmac');

MD4.hash = function hash() {
  return new MD4();
};

MD4.hmac = function hmac() {
  return new HMAC(MD4, 64);
};

MD4.mac = function mac(data, key) {
  return MD4.hmac().init(key).update(data).final();
};

MD4.native = 2;
MD4.id = 'MD4';
MD4.size = 16;
MD4.bits = 128;
MD4.blockSize = 64;
MD4.zero = Buffer.alloc(16, 0x00);
MD4.ctx = new MD4();

module.exports = MD4;
