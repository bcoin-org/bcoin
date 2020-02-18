/*!
 * kmac128.js - KMAC128 implementation for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const KMAC = require('./kmac');

/**
 * KMAC128
 */

class KMAC128 extends KMAC {
  constructor() {
    super();
  }

  init(key, pers) {
    return super.init(128, key, pers);
  }

  static hash() {
    return new KMAC128();
  }

  static hmac(key, pers, len) {
    return super.hmac(128, key, pers, len);
  }

  static digest(data, key, pers, len) {
    return super.digest(data, 128, key, pers, len);
  }

  static root(left, right, key, pers, len) {
    return super.root(left, right, 128, key, pers, len);
  }

  static multi(x, y, z, key, pers, len) {
    return super.multi(x, y, z, 128, key, pers, len);
  }

  static mac(data, salt, key, pers, len) {
    return super.mac(data, salt, 128, key, pers, len);
  }
}

KMAC128.native = KMAC.native;
KMAC128.id = 'KMAC128';
KMAC128.size = 16;
KMAC128.bits = 128;
KMAC128.blockSize = 168;
KMAC128.zero = Buffer.alloc(16, 0x00);
KMAC128.ctx = new KMAC128();

/*
 * Expose
 */

module.exports = KMAC128;
