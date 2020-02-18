/*!
 * blake2b.js - BLAKE2b implementation for bcrypto
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const {BLAKE2b} = require('./binding');
const HMAC = require('../internal/hmac');

BLAKE2b.hash = function hash() {
  return new BLAKE2b();
};

BLAKE2b.hmac = function hmac(size = 256) {
  return new HMAC(BLAKE2b, 128, [size]);
};

BLAKE2b.mac = function mac(data, key, size = 32) {
  return BLAKE2b.hmac(size).init(key).update(data).final();
};

BLAKE2b.native = 2;
BLAKE2b.id = 'BLAKE2B256';
BLAKE2b.size = 32;
BLAKE2b.bits = 256;
BLAKE2b.blockSize = 128;
BLAKE2b.zero = Buffer.alloc(32, 0x00);
BLAKE2b.ctx = new BLAKE2b();

module.exports = BLAKE2b;
