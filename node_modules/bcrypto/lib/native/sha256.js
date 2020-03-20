/*!
 * sha256.js - SHA256 implementation for bcrypto
 * Copyright (c) 2016-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const {Hash, HMAC, hashes} = require('./hash');

/*
 * SHA256
 */

class SHA256 extends Hash {
  constructor() {
    super(hashes.SHA256);
  }

  static hash() {
    return new SHA256();
  }

  static hmac() {
    return new HMAC(hashes.SHA256);
  }

  static digest(data) {
    return Hash.digest(hashes.SHA256, data);
  }

  static root(left, right) {
    return Hash.root(hashes.SHA256, left, right);
  }

  static multi(x, y, z) {
    return Hash.multi(hashes.SHA256, x, y, z);
  }

  static mac(data, key) {
    return HMAC.digest(hashes.SHA256, data, key);
  }
}

/*
 * Static
 */

SHA256.native = 2;
SHA256.id = 'SHA256';
SHA256.size = 32;
SHA256.bits = 256;
SHA256.blockSize = 64;
SHA256.zero = Buffer.alloc(32, 0x00);
SHA256.ctx = new SHA256();

/*
 * Expose
 */

module.exports = SHA256;
