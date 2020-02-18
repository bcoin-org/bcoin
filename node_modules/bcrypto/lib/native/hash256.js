/*!
 * hash256.js - hash256 implementation for bcrypto
 * Copyright (c) 2016-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 * Parts of this software based on hash.js.
 */

'use strict';

const {Hash256} = require('./binding');
const HMAC = require('../internal/hmac');

Hash256.hash = function hash() {
  return new Hash256();
};

Hash256.hmac = function hmac() {
  return new HMAC(Hash256, 64);
};

Hash256.mac = function mac(data, key) {
  return Hash256.hmac().init(key).update(data).final();
};

Hash256.native = 2;
Hash256.id = 'HASH256';
Hash256.size = 32;
Hash256.bits = 256;
Hash256.blockSize = 64;
Hash256.zero = Buffer.alloc(32, 0x00);
Hash256.ctx = new Hash256();

module.exports = Hash256;
