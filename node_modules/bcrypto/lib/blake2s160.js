/*!
 * blake2s160.js - BLAKE2s implementation for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const BLAKE2s = require('./blake2s');

/**
 * BLAKE2s160
 */

class BLAKE2s160 extends BLAKE2s {
  constructor() {
    super();
  }

  init(key) {
    return super.init(20, key);
  }

  static hash() {
    return new BLAKE2s160();
  }

  static hmac() {
    return super.hmac(20);
  }

  static digest(data, key) {
    return super.digest(data, 20, key);
  }

  static root(left, right, key) {
    return super.root(left, right, 20, key);
  }

  static multi(x, y, z, key) {
    return super.multi(x, y, z, 20, key);
  }

  static mac(data, key) {
    return super.mac(data, key, 20);
  }
}

/*
 * Static
 */

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
