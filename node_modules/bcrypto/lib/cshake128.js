/*!
 * cshake128.js - CSHAKE128 implementation for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const CSHAKE = require('./cshake');

/**
 * CSHAKE128
 */

class CSHAKE128 extends CSHAKE {
  constructor() {
    super();
  }

  init(name, pers) {
    return super.init(128, name, pers);
  }

  static hash() {
    return new CSHAKE128();
  }

  static hmac(name, pers, len) {
    return super.hmac(128, name, pers, len);
  }

  static digest(data, name, pers, len) {
    return super.digest(data, 128, name, pers, len);
  }

  static root(left, right, name, pers, len) {
    return super.root(left, right, 128, name, pers, len);
  }

  static multi(x, y, z, name, pers, len) {
    return super.multi(x, y, z, 128, name, pers, len);
  }

  static mac(data, key, name, pers, len) {
    return super.mac(data, key, 128, name, pers, len);
  }
}

/*
 * Static
 */

CSHAKE128.native = CSHAKE.native;
CSHAKE128.id = 'CSHAKE128';
CSHAKE128.size = 16;
CSHAKE128.bits = 128;
CSHAKE128.blockSize = 168;
CSHAKE128.zero = Buffer.alloc(16, 0x00);
CSHAKE128.ctx = new CSHAKE128();

/*
 * Expose
 */

module.exports = CSHAKE128;
