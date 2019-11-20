/*!
 * sha3.js - SHA3 implementation for bcrypto
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const {Keccak} = require('./binding');

class SHA3 extends Keccak {
  constructor() {
    super();
  }

  final() {
    return super.final(0x06, null);
  }

  static hash() {
    return new SHA3();
  }

  static hmac(bits = 256) {
    return super.hmac(bits, 0x06, null);
  }

  static digest(data, bits = 256) {
    return super.digest(data, bits, 0x06, null);
  }

  static root(left, right, bits = 256) {
    return super.root(left, right, bits, 0x06, null);
  }

  static multi(x, y, z, bits = 256) {
    return super.multi(x, y, z, bits, 0x06, null);
  }

  static mac(data, key, bits = 256) {
    return super.mac(data, key, bits, 0x06, null);
  }
}

SHA3.native = 2;
SHA3.id = 'SHA3_256';
SHA3.size = 32;
SHA3.bits = 256;
SHA3.blockSize = 136;
SHA3.zero = Buffer.alloc(32, 0x00);
SHA3.ctx = new SHA3();

module.exports = SHA3;
