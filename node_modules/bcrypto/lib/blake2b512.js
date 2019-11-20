/*!
 * blake2b512.js - BLAKE2b implementation for bcoin
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const BLAKE2b = require('./blake2b');

/**
 * BLAKE2b512
 */

class BLAKE2b512 extends BLAKE2b {
  /**
   * Create a BLAKE2b512 context.
   * @constructor
   */

  constructor() {
    super();
  }

  init(key = null) {
    return super.init(64, key);
  }

  static hash() {
    return new BLAKE2b512();
  }

  static hmac() {
    return super.hmac(64);
  }

  static digest(data, key = null) {
    return super.digest(data, 64, key);
  }

  static root(left, right) {
    return super.root(left, right, 64);
  }

  static multi(x, y, z) {
    return super.multi(x, y, z, 64);
  }

  static mac(data, key) {
    return super.mac(data, key, 64);
  }
}

BLAKE2b512.native = BLAKE2b.native;
BLAKE2b512.id = 'BLAKE2B512';
BLAKE2b512.size = 64;
BLAKE2b512.bits = 512;
BLAKE2b512.blockSize = 128;
BLAKE2b512.zero = Buffer.alloc(64, 0x00);
BLAKE2b512.ctx = new BLAKE2b512();

/*
 * Expose
 */

module.exports = BLAKE2b512;
