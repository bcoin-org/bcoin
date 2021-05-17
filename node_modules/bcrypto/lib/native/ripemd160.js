/*!
 * ripemd160.js - RIPEMD160 implementation for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const {Hash, HMAC, hashes} = require('./hash');

/*
 * RIPEMD160
 */

class RIPEMD160 extends Hash {
  constructor() {
    super(hashes.RIPEMD160);
  }

  static hash() {
    return new RIPEMD160();
  }

  static hmac() {
    return new HMAC(hashes.RIPEMD160);
  }

  static digest(data) {
    return Hash.digest(hashes.RIPEMD160, data);
  }

  static root(left, right) {
    return Hash.root(hashes.RIPEMD160, left, right);
  }

  static multi(x, y, z) {
    return Hash.multi(hashes.RIPEMD160, x, y, z);
  }

  static mac(data, key) {
    return HMAC.digest(hashes.RIPEMD160, data, key);
  }
}

/*
 * Static
 */

RIPEMD160.native = 2;
RIPEMD160.id = 'RIPEMD160';
RIPEMD160.size = 20;
RIPEMD160.bits = 160;
RIPEMD160.blockSize = 64;
RIPEMD160.zero = Buffer.alloc(20, 0x00);
RIPEMD160.ctx = new RIPEMD160();

/*
 * Expose
 */

module.exports = RIPEMD160;
