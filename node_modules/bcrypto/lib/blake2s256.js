/*!
 * blake2s256.js - BLAKE2s implementation for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const BLAKE2s = require('./blake2s');

/**
 * BLAKE2s256
 */

class BLAKE2s256 extends BLAKE2s {
  constructor() {
    super();
  }

  init(key) {
    return super.init(32, key);
  }

  static hash() {
    return new BLAKE2s256();
  }

  static hmac() {
    return super.hmac(32);
  }

  static digest(data, key) {
    return super.digest(data, 32, key);
  }

  static root(left, right, key) {
    return super.root(left, right, 32, key);
  }

  static multi(x, y, z, key) {
    return super.multi(x, y, z, 32, key);
  }

  static mac(data, key) {
    return super.mac(data, key, 32);
  }
}

/*
 * Static
 */

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
