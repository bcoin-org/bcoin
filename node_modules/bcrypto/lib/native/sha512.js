/*!
 * sha512.js - SHA512 implementation for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const {Hash, HMAC, hashes} = require('./hash');

/*
 * SHA512
 */

class SHA512 extends Hash {
  constructor() {
    super(hashes.SHA512);
  }

  static hash() {
    return new SHA512();
  }

  static hmac() {
    return new HMAC(hashes.SHA512);
  }

  static digest(data) {
    return Hash.digest(hashes.SHA512, data);
  }

  static root(left, right) {
    return Hash.root(hashes.SHA512, left, right);
  }

  static multi(x, y, z) {
    return Hash.multi(hashes.SHA512, x, y, z);
  }

  static mac(data, key) {
    return HMAC.digest(hashes.SHA512, data, key);
  }
}

/*
 * Static
 */

SHA512.native = 2;
SHA512.id = 'SHA512';
SHA512.size = 64;
SHA512.bits = 512;
SHA512.blockSize = 128;
SHA512.zero = Buffer.alloc(64, 0x00);
SHA512.ctx = new SHA512();

/*
 * Expose
 */

module.exports = SHA512;
