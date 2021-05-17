/*!
 * sha3-224.js - sha3-224 implementation for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const SHA3 = require('./sha3');

/**
 * SHA3-224
 */

class SHA3_224 extends SHA3 {
  constructor() {
    super();
  }

  init() {
    return super.init(224);
  }

  static hash() {
    return new SHA3_224();
  }

  static hmac() {
    return super.hmac(224);
  }

  static digest(data) {
    return super.digest(data, 224);
  }

  static root(left, right) {
    return super.root(left, right, 224);
  }

  static multi(x, y, z) {
    return super.multi(x, y, z, 224);
  }

  static mac(data, key) {
    return super.mac(data, key, 224);
  }
}

/*
 * Static
 */

SHA3_224.native = SHA3.native;
SHA3_224.id = 'SHA3_224';
SHA3_224.size = 28;
SHA3_224.bits = 224;
SHA3_224.blockSize = 144;
SHA3_224.zero = Buffer.alloc(28, 0x00);
SHA3_224.ctx = new SHA3_224();

/*
 * Expose
 */

module.exports = SHA3_224;
