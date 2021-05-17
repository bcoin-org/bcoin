/*!
 * gost94.js - gost94 implementation for bcrypto
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const {Hash, HMAC, hashes} = require('./hash');

/*
 * GOST94
 */

class GOST94 extends Hash {
  constructor() {
    super(hashes.GOST94);
  }

  static hash() {
    return new GOST94();
  }

  static hmac() {
    return new HMAC(hashes.GOST94);
  }

  static digest(data) {
    return Hash.digest(hashes.GOST94, data);
  }

  static root(left, right) {
    return Hash.root(hashes.GOST94, left, right);
  }

  static multi(x, y, z) {
    return Hash.multi(hashes.GOST94, x, y, z);
  }

  static mac(data, key) {
    return HMAC.digest(hashes.GOST94, data, key);
  }
}

/*
 * Static
 */

GOST94.native = 2;
GOST94.id = 'GOST94';
GOST94.size = 32;
GOST94.bits = 256;
GOST94.blockSize = 32;
GOST94.zero = Buffer.alloc(32, 0x00);
GOST94.ctx = new GOST94();

/*
 * Expose
 */

module.exports = GOST94;
