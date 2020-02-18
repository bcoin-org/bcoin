/*!
 * sha3-384.js - sha3-384 implementation for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const SHA3 = require('./sha3');

/**
 * SHA3-384
 */

class SHA3_384 extends SHA3 {
  constructor() {
    super();
  }

  init() {
    return super.init(384);
  }

  static hash() {
    return new SHA3_384();
  }

  static hmac() {
    return super.hmac(384);
  }

  static digest(data) {
    return super.digest(data, 384);
  }

  static root(left, right) {
    return super.root(left, right, 384);
  }

  static multi(x, y, z) {
    return super.multi(x, y, z, 384);
  }

  static mac(data, key) {
    return super.mac(data, key, 384);
  }
}

/*
 * Static
 */

SHA3_384.native = SHA3.native;
SHA3_384.id = 'SHA3_384';
SHA3_384.size = 48;
SHA3_384.bits = 384;
SHA3_384.blockSize = 104;
SHA3_384.zero = Buffer.alloc(48, 0x00);
SHA3_384.ctx = new SHA3_384();

/*
 * Expose
 */

module.exports = SHA3_384;
