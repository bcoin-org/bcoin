/*!
 * sha3-256.js - sha3-256 implementation for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const SHA3 = require('./sha3');

/**
 * SHA3-256
 */

class SHA3_256 extends SHA3 {
  constructor() {
    super();
  }

  init() {
    return super.init(256);
  }

  static hash() {
    return new SHA3_256();
  }

  static hmac() {
    return super.hmac(256);
  }

  static digest(data) {
    return super.digest(data, 256);
  }

  static root(left, right) {
    return super.root(left, right, 256);
  }

  static multi(x, y, z) {
    return super.multi(x, y, z, 256);
  }

  static mac(data, key) {
    return super.mac(data, key, 256);
  }
}

/*
 * Static
 */

SHA3_256.native = SHA3.native;
SHA3_256.id = 'SHA3_256';
SHA3_256.size = 32;
SHA3_256.bits = 256;
SHA3_256.blockSize = 136;
SHA3_256.zero = Buffer.alloc(32, 0x00);
SHA3_256.ctx = new SHA3_256();

/*
 * Expose
 */

module.exports = SHA3_256;
