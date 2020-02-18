/*!
 * shake128.js - SHAKE128 implementation for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const SHAKE = require('./shake');

/**
 * SHAKE128
 */

class SHAKE128 extends SHAKE {
  constructor() {
    super();
  }

  init() {
    return super.init(128);
  }

  static hash() {
    return new SHAKE128();
  }

  static hmac(len) {
    return super.hmac(128, len);
  }

  static digest(data, len) {
    return super.digest(data, 128, len);
  }

  static root(left, right, len) {
    return super.root(left, right, 128, len);
  }

  static multi(x, y, z, len) {
    return super.multi(x, y, z, 128, len);
  }

  static mac(data, key, len) {
    return super.mac(data, key, 128, len);
  }
}

/*
 * Static
 */

SHAKE128.native = SHAKE.native;
SHAKE128.id = 'SHAKE128';
SHAKE128.size = 16;
SHAKE128.bits = 128;
SHAKE128.blockSize = 168;
SHAKE128.zero = Buffer.alloc(16, 0x00);
SHAKE128.ctx = new SHAKE128();

/*
 * Expose
 */

module.exports = SHAKE128;
