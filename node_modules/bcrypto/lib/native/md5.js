/*!
 * md5.js - MD5 implementation for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const {Hash, HMAC, hashes} = require('./hash');

/*
 * MD5
 */

class MD5 extends Hash {
  constructor() {
    super(hashes.MD5);
  }

  static hash() {
    return new MD5();
  }

  static hmac() {
    return new HMAC(hashes.MD5);
  }

  static digest(data) {
    return Hash.digest(hashes.MD5, data);
  }

  static root(left, right) {
    return Hash.root(hashes.MD5, left, right);
  }

  static multi(x, y, z) {
    return Hash.multi(hashes.MD5, x, y, z);
  }

  static mac(data, key) {
    return HMAC.digest(hashes.MD5, data, key);
  }
}

/*
 * Static
 */

MD5.native = 2;
MD5.id = 'MD5';
MD5.size = 16;
MD5.bits = 128;
MD5.blockSize = 64;
MD5.zero = Buffer.alloc(16, 0x00);
MD5.ctx = new MD5();

/*
 * Expose
 */

module.exports = MD5;
