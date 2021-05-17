/*!
 * kmac256.js - KMAC256 implementation for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const KMAC = require('./kmac');

/**
 * KMAC256
 */

class KMAC256 extends KMAC {
  constructor() {
    super();
  }

  init(key, pers) {
    return super.init(256, key, pers);
  }

  static hash() {
    return new KMAC256();
  }

  static hmac(key, pers, len) {
    return super.hmac(256, key, pers, len);
  }

  static digest(data, key, pers, len) {
    return super.digest(data, 256, key, pers, len);
  }

  static root(left, right, key, pers, len) {
    return super.root(left, right, 256, key, pers, len);
  }

  static multi(x, y, z, key, pers, len) {
    return super.multi(x, y, z, 256, key, pers, len);
  }

  static mac(data, salt, key, pers, len) {
    return super.mac(data, salt, 256, key, pers, len);
  }
}

KMAC256.native = KMAC.native;
KMAC256.id = 'KMAC256';
KMAC256.size = 32;
KMAC256.bits = 256;
KMAC256.blockSize = 136;
KMAC256.zero = Buffer.alloc(32, 0x00);
KMAC256.ctx = new KMAC256();

/*
 * Expose
 */

module.exports = KMAC256;
