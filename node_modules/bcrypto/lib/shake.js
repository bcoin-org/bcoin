/*!
 * shake.js - SHAKE implementation for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/SHA-3
 *   https://keccak.team/specifications.html
 *   https://csrc.nist.gov/projects/hash-functions/sha-3-project/sha-3-standardization
 *   http://dx.doi.org/10.6028/NIST.FIPS.202
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

  static hmac(bits, len) {
    return super.hmac(bits, 0x1f, len);
  }

  static digest(data, bits, len) {
    return super.digest(data, bits, 0x1f, len);
  }

  static root(left, right, bits, len) {
    return super.root(left, right, bits, 0x1f, len);
  }

  static multi(x, y, z, bits, len) {
    return super.multi(x, y, z, bits, 0x1f, len);
  }

  static mac(data, key, bits, len) {
    return super.mac(data, key, bits, 0x1f, len);
  }
}

/*
 * Static
 */

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
