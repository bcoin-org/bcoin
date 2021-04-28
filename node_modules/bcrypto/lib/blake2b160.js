/*!
 * blake2b160.js - BLAKE2b implementation for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const BLAKE2b = require('./blake2b');

/**
 * BLAKE2b160
 */

class BLAKE2b160 extends BLAKE2b {
  constructor() {
    super();
  }

  init(key) {
    return super.init(20, key);
  }

  static hash() {
    return new BLAKE2b160();
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

BLAKE2b160.native = BLAKE2b.native;
BLAKE2b160.id = 'BLAKE2B160';
BLAKE2b160.size = 20;
BLAKE2b160.bits = 160;
BLAKE2b160.blockSize = 128;
BLAKE2b160.zero = Buffer.alloc(20, 0x00);
BLAKE2b160.ctx = new BLAKE2b160();

/*
 * Expose
 */

module.exports = BLAKE2b160;
