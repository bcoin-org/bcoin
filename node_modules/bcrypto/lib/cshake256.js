/*!
 * cshake256.js - CSHAKE256 implementation for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const CSHAKE = require('./cshake');

/**
 * CSHAKE256
 */

class CSHAKE256 extends CSHAKE {
  constructor() {
    super();
  }

  init(name, pers) {
    return super.init(256, name, pers);
  }

  static hash() {
    return new CSHAKE256();
  }

  static hmac(name, pers, len) {
    return super.hmac(256, name, pers, len);
  }

  static digest(data, name, pers, len) {
    return super.digest(data, 256, name, pers, len);
  }

  static root(left, right, name, pers, len) {
    return super.root(left, right, 256, name, pers, len);
  }

  static multi(x, y, z, name, pers, len) {
    return super.multi(x, y, z, 256, name, pers, len);
  }

  static mac(data, key, name, pers, len) {
    return super.mac(data, key, 256, name, pers, len);
  }
}

/*
 * Static
 */

CSHAKE256.native = CSHAKE.native;
CSHAKE256.id = 'CSHAKE256';
CSHAKE256.size = 32;
CSHAKE256.bits = 256;
CSHAKE256.blockSize = 136;
CSHAKE256.zero = Buffer.alloc(32, 0x00);
CSHAKE256.ctx = new CSHAKE256();

/*
 * Expose
 */

module.exports = CSHAKE256;
