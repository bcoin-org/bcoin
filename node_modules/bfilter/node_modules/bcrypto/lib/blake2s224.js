/*!
 * blake2s224.js - BLAKE2s implementation for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const BLAKE2s = require('./blake2s');

/**
 * BLAKE2s224
 */

class BLAKE2s224 extends BLAKE2s {
  constructor() {
    super();
  }

  init(key) {
    return super.init(28, key);
  }

  static hash() {
    return new BLAKE2s224();
  }

  static hmac() {
    return super.hmac(28);
  }

  static digest(data, key) {
    return super.digest(data, 28, key);
  }

  static root(left, right, key) {
    return super.root(left, right, 28, key);
  }

  static multi(x, y, z, key) {
    return super.multi(x, y, z, 28, key);
  }

  static mac(data, key) {
    return super.mac(data, key, 28);
  }
}

/*
 * Static
 */

BLAKE2s224.native = BLAKE2s.native;
BLAKE2s224.id = 'BLAKE2S224';
BLAKE2s224.size = 28;
BLAKE2s224.bits = 224;
BLAKE2s224.blockSize = 64;
BLAKE2s224.zero = Buffer.alloc(28, 0x00);
BLAKE2s224.ctx = new BLAKE2s224();

/*
 * Expose
 */

module.exports = BLAKE2s224;
