/*!
 * hash160.js - hash160 implementation for bcrypto
 * Copyright (c) 2016-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const {Hash, HMAC, hashes} = require('./hash');

/*
 * Hash160
 */

class Hash160 extends Hash {
  constructor() {
    super(hashes.HASH160);
  }

  static hash() {
    return new Hash160();
  }

  static hmac() {
    return new HMAC(hashes.HASH160);
  }

  static digest(data) {
    return Hash.digest(hashes.HASH160, data);
  }

  static root(left, right) {
    return Hash.root(hashes.HASH160, left, right);
  }

  static multi(x, y, z) {
    return Hash.multi(hashes.HASH160, x, y, z);
  }

  static mac(data, key) {
    return HMAC.digest(hashes.HASH160, data, key);
  }
}

/*
 * Static
 */

Hash160.native = 2;
Hash160.id = 'HASH160';
Hash160.size = 20;
Hash160.bits = 160;
Hash160.blockSize = 64;
Hash160.zero = Buffer.alloc(20, 0x00);
Hash160.ctx = new Hash160();

/*
 * Expose
 */

module.exports = Hash160;
