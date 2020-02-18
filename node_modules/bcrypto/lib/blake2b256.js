/*!
 * blake2b256.js - BLAKE2b implementation for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const BLAKE2b = require('./blake2b');

/**
 * BLAKE2b256
 */

class BLAKE2b256 extends BLAKE2b {
  constructor() {
    super();
  }

  init(key) {
    return super.init(32, key);
  }

  static hash() {
    return new BLAKE2b256();
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

BLAKE2b256.native = BLAKE2b.native;
BLAKE2b256.id = 'BLAKE2B256';
BLAKE2b256.size = 32;
BLAKE2b256.bits = 256;
BLAKE2b256.blockSize = 128;
BLAKE2b256.zero = Buffer.alloc(32, 0x00);
BLAKE2b256.ctx = new BLAKE2b256();

/*
 * Expose
 */

module.exports = BLAKE2b256;
