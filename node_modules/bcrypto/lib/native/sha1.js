/*!
 * sha1.js - SHA1 implementation for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const {Hash, HMAC, hashes} = require('./hash');

/*
 * SHA1
 */

class SHA1 extends Hash {
  constructor() {
    super(hashes.SHA1);
  }

  static hash() {
    return new SHA1();
  }

  static hmac() {
    return new HMAC(hashes.SHA1);
  }

  static digest(data) {
    return Hash.digest(hashes.SHA1, data);
  }

  static root(left, right) {
    return Hash.root(hashes.SHA1, left, right);
  }

  static multi(x, y, z) {
    return Hash.multi(hashes.SHA1, x, y, z);
  }

  static mac(data, key) {
    return HMAC.digest(hashes.SHA1, data, key);
  }
}

/*
 * Static
 */

SHA1.native = 2;
SHA1.id = 'SHA1';
SHA1.size = 20;
SHA1.bits = 160;
SHA1.blockSize = 64;
SHA1.zero = Buffer.alloc(20, 0x00);
SHA1.ctx = new SHA1();

/*
 * Expose
 */

module.exports = SHA1;
