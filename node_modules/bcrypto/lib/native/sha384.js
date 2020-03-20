/*!
 * sha384.js - SHA384 implementation for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const {Hash, HMAC, hashes} = require('./hash');

/*
 * SHA384
 */

class SHA384 extends Hash {
  constructor() {
    super(hashes.SHA384);
  }

  static hash() {
    return new SHA384();
  }

  static hmac() {
    return new HMAC(hashes.SHA384);
  }

  static digest(data) {
    return Hash.digest(hashes.SHA384, data);
  }

  static root(left, right) {
    return Hash.root(hashes.SHA384, left, right);
  }

  static multi(x, y, z) {
    return Hash.multi(hashes.SHA384, x, y, z);
  }

  static mac(data, key) {
    return HMAC.digest(hashes.SHA384, data, key);
  }
}

/*
 * Static
 */

SHA384.native = 2;
SHA384.id = 'SHA384';
SHA384.size = 48;
SHA384.bits = 384;
SHA384.blockSize = 128;
SHA384.zero = Buffer.alloc(48, 0x00);
SHA384.ctx = new SHA384();

/*
 * Expose
 */

module.exports = SHA384;
