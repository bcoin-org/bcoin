/*!
 * md4.js - MD4 implementation for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const {Hash, HMAC, hashes} = require('./hash');

/*
 * MD4
 */

class MD4 extends Hash {
  constructor() {
    super(hashes.MD4);
  }

  static hash() {
    return new MD4();
  }

  static hmac() {
    return new HMAC(hashes.MD4);
  }

  static digest(data) {
    return Hash.digest(hashes.MD4, data);
  }

  static root(left, right) {
    return Hash.root(hashes.MD4, left, right);
  }

  static multi(x, y, z) {
    return Hash.multi(hashes.MD4, x, y, z);
  }

  static mac(data, key) {
    return HMAC.digest(hashes.MD4, data, key);
  }
}

/*
 * Static
 */

MD4.native = 2;
MD4.id = 'MD4';
MD4.size = 16;
MD4.bits = 128;
MD4.blockSize = 64;
MD4.zero = Buffer.alloc(16, 0x00);
MD4.ctx = new MD4();

/*
 * Expose
 */

module.exports = MD4;
