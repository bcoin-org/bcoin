/*!
 * sha224.js - SHA224 implementation for bcrypto
 * Copyright (c) 2016-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const {Hash, HMAC, hashes} = require('./hash');

/*
 * SHA224
 */

class SHA224 extends Hash {
  constructor() {
    super(hashes.SHA224);
  }

  static hash() {
    return new SHA224();
  }

  static hmac() {
    return new HMAC(hashes.SHA224);
  }

  static digest(data) {
    return Hash.digest(hashes.SHA224, data);
  }

  static root(left, right) {
    return Hash.root(hashes.SHA224, left, right);
  }

  static multi(x, y, z) {
    return Hash.multi(hashes.SHA224, x, y, z);
  }

  static mac(data, key) {
    return HMAC.digest(hashes.SHA224, data, key);
  }
}

/*
 * Static
 */

SHA224.native = 2;
SHA224.id = 'SHA224';
SHA224.size = 28;
SHA224.bits = 224;
SHA224.blockSize = 64;
SHA224.zero = Buffer.alloc(28, 0x00);
SHA224.ctx = new SHA224();

/*
 * Expose
 */

module.exports = SHA224;
