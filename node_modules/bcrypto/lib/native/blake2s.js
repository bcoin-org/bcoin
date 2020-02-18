/*!
 * blake2s.js - BLAKE2s implementation for bcrypto
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const {BLAKE2s} = require('./binding');
const HMAC = require('../internal/hmac');

BLAKE2s.hash = function hash() {
  return new BLAKE2s();
};

BLAKE2s.hmac = function hmac(size = 32) {
  return new HMAC(BLAKE2s, 64, [size]);
};

BLAKE2s.mac = function mac(data, key, size = 32) {
  return BLAKE2s.hmac(size).init(key).update(data).final();
};

BLAKE2s.native = 2;
BLAKE2s.id = 'BLAKE2S256';
BLAKE2s.size = 32;
BLAKE2s.bits = 256;
BLAKE2s.blockSize = 64;
BLAKE2s.zero = Buffer.alloc(32, 0x00);
BLAKE2s.ctx = new BLAKE2s();

module.exports = BLAKE2s;
