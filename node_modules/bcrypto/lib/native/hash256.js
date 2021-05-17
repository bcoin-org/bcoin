/*!
 * hash256.js - hash256 implementation for bcrypto
 * Copyright (c) 2016-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const {Hash, HMAC, hashes} = require('./hash');

/*
 * Hash256
 */

class Hash256 extends Hash {
  constructor() {
    super(hashes.HASH256);
  }

  static hash() {
    return new Hash256();
  }

  static hmac() {
    return new HMAC(hashes.HASH256);
  }

  static digest(data) {
    return Hash.digest(hashes.HASH256, data);
  }

  static root(left, right) {
    return Hash.root(hashes.HASH256, left, right);
  }

  static multi(x, y, z) {
    return Hash.multi(hashes.HASH256, x, y, z);
  }

  static mac(data, key) {
    return HMAC.digest(hashes.HASH256, data, key);
  }
}

/*
 * Static
 */

Hash256.native = 2;
Hash256.id = 'HASH256';
Hash256.size = 32;
Hash256.bits = 256;
Hash256.blockSize = 64;
Hash256.zero = Buffer.alloc(32, 0x00);
Hash256.ctx = new Hash256();

/*
 * Expose
 */

module.exports = Hash256;
