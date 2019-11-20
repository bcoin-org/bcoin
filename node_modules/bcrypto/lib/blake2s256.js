/*!
 * blake2s256.js - BLAKE2s implementation for bcoin
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const BLAKE2s = require('./blake2s');

/**
 * BLAKE2s256
 */

class BLAKE2s256 extends BLAKE2s {
  /**
   * Create a BLAKE2s256 context.
   * @constructor
   */

  constructor() {
    super();
  }

  init(key = null) {
    return super.init(32, key);
  }

  static hash() {
    return new BLAKE2s256();
  }

  static hmac() {
    return super.hmac(32);
  }

  static digest(data, key = null) {
    return super.digest(data, 32, key);
  }

  static root(left, right) {
    return super.root(left, right, 32);
  }

  static multi(x, y, z) {
    return super.multi(x, y, z, 32);
  }

  static mac(data, key) {
    return super.mac(data, key, 32);
  }
}

BLAKE2s256.native = BLAKE2s.native;
BLAKE2s256.id = 'BLAKE2S256';
BLAKE2s256.size = 32;
BLAKE2s256.bits = 256;
BLAKE2s256.blockSize = 64;
BLAKE2s256.zero = Buffer.alloc(32, 0x00);
BLAKE2s256.ctx = new BLAKE2s256();

/*
 * Expose
 */

module.exports = BLAKE2s256;
