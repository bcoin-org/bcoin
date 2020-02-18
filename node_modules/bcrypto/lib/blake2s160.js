/*!
 * blake2s160.js - BLAKE2s implementation for bcoin
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const BLAKE2s = require('./blake2s');

/**
 * BLAKE2s160
 */

class BLAKE2s160 extends BLAKE2s {
  /**
   * Create a BLAKE2s160 context.
   * @constructor
   */

  constructor() {
    super();
  }

  init(key = null) {
    return super.init(20, key);
  }

  static hash() {
    return new BLAKE2s160();
  }

  static hmac() {
    return super.hmac(20);
  }

  static digest(data, key = null) {
    return super.digest(data, 20, key);
  }

  static root(left, right) {
    return super.root(left, right, 20);
  }

  static multi(x, y, z) {
    return super.multi(x, y, z, 20);
  }

  static mac(data, key) {
    return super.mac(data, key, 20);
  }
}

BLAKE2s160.native = BLAKE2s.native;
BLAKE2s160.id = 'BLAKE2S160';
BLAKE2s160.size = 20;
BLAKE2s160.bits = 160;
BLAKE2s160.blockSize = 64;
BLAKE2s160.zero = Buffer.alloc(20, 0x00);
BLAKE2s160.ctx = new BLAKE2s160();

/*
 * Expose
 */

module.exports = BLAKE2s160;
