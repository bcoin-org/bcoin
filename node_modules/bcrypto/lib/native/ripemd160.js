/*!
 * ripemd160.js - RIPEMD160 implementation for bcrypto
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const {RIPEMD160} = require('./binding');
const HMAC = require('../internal/hmac');

RIPEMD160.hash = function hash() {
  return new RIPEMD160();
};

RIPEMD160.hmac = function hmac() {
  return new HMAC(RIPEMD160, 64);
};

RIPEMD160.mac = function mac(data, key) {
  return RIPEMD160.hmac().init(key).update(data).final();
};

RIPEMD160.native = 2;
RIPEMD160.id = 'RIPEMD160';
RIPEMD160.size = 20;
RIPEMD160.bits = 160;
RIPEMD160.blockSize = 64;
RIPEMD160.zero = Buffer.alloc(20, 0x00);
RIPEMD160.ctx = new RIPEMD160();

module.exports = RIPEMD160;
