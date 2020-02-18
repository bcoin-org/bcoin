/*!
 * shake.js - SHAKE implementation for bcrypto
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const Keccak = require('./keccak');

/**
 * SHAKE
 */

class SHAKE extends Keccak {
  /**
   * Create a SHAKE Context.
   * @constructor
   */

  constructor() {
    super();
  }

  final(len) {
    return super.final(0x1f, len);
  }

  static hash() {
    return new SHAKE();
  }

  static hmac(bits = 256, len) {
    return super.hmac(bits, 0x1f, len);
  }

  static digest(data, bits = 256, len) {
    return super.digest(data, bits, 0x1f, len);
  }

  static root(left, right, bits = 256, len) {
    return super.root(left, right, bits, 0x1f, len);
  }

  static multi(x, y, z, bits = 256, len) {
    return super.multi(x, y, z, bits, 0x1f, len);
  }

  static mac(data, key, bits = 256, len) {
    return super.mac(data, key, bits, 0x1f, len);
  }
}

SHAKE.native = Keccak.native;
SHAKE.id = 'SHAKE256';
SHAKE.size = 32;
SHAKE.bits = 256;
SHAKE.blockSize = 136;
SHAKE.zero = Buffer.alloc(32, 0x00);
SHAKE.ctx = new SHAKE();

/*
 * Expose
 */

module.exports = SHAKE;
