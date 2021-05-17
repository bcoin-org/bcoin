/*!
 * shake256.js - SHAKE256 implementation for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const SHAKE = require('./shake');

/**
 * SHAKE256
 */

class SHAKE256 extends SHAKE {
  constructor() {
    super();
  }

  init() {
    return super.init(256);
  }

  static hash() {
    return new SHAKE256();
  }

  static hmac(len) {
    return super.hmac(256, len);
  }

  static digest(data, len) {
    return super.digest(data, 256, len);
  }

  static root(left, right, len) {
    return super.root(left, right, 256, len);
  }

  static multi(x, y, z, len) {
    return super.multi(x, y, z, 256, len);
  }

  static mac(data, key, len) {
    return super.mac(data, key, 256, len);
  }
}

/*
 * Static
 */

SHAKE256.native = SHAKE.native;
SHAKE256.id = 'SHAKE256';
SHAKE256.size = 32;
SHAKE256.bits = 256;
SHAKE256.blockSize = 136;
SHAKE256.zero = Buffer.alloc(32, 0x00);
SHAKE256.ctx = new SHAKE256();

/*
 * Expose
 */

module.exports = SHAKE256;
