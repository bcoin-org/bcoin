/*!
 * blake2b384.js - BLAKE2b implementation for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const BLAKE2b = require('./blake2b');

/**
 * BLAKE2b384
 */

class BLAKE2b384 extends BLAKE2b {
  constructor() {
    super();
  }

  init(key) {
    return super.init(48, key);
  }

  static hash() {
    return new BLAKE2b384();
  }

  static hmac() {
    return super.hmac(48);
  }

  static digest(data, key) {
    return super.digest(data, 48, key);
  }

  static root(left, right, key) {
    return super.root(left, right, 48, key);
  }

  static multi(x, y, z, key) {
    return super.multi(x, y, z, 48, key);
  }

  static mac(data, key) {
    return super.mac(data, key, 48);
  }
}

/*
 * Static
 */

BLAKE2b384.native = BLAKE2b.native;
BLAKE2b384.id = 'BLAKE2B384';
BLAKE2b384.size = 48;
BLAKE2b384.bits = 384;
BLAKE2b384.blockSize = 128;
BLAKE2b384.zero = Buffer.alloc(48, 0x00);
BLAKE2b384.ctx = new BLAKE2b384();

/*
 * Expose
 */

module.exports = BLAKE2b384;
