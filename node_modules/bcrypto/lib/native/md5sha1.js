/*!
 * md5sha1.js - MD5SHA1 implementation for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const {Hash, HMAC, hashes} = require('./hash');

/*
 * MD5SHA1
 */

class MD5SHA1 extends Hash {
  constructor() {
    super(hashes.MD5SHA1);
  }

  static hash() {
    return new MD5SHA1();
  }

  static hmac() {
    return new HMAC(hashes.MD5SHA1);
  }

  static digest(data) {
    return Hash.digest(hashes.MD5SHA1, data);
  }

  static root(left, right) {
    return Hash.root(hashes.MD5SHA1, left, right);
  }

  static multi(x, y, z) {
    return Hash.multi(hashes.MD5SHA1, x, y, z);
  }

  static mac(data, key) {
    return HMAC.digest(hashes.MD5SHA1, data, key);
  }
}

/*
 * Static
 */

MD5SHA1.native = 2;
MD5SHA1.id = 'MD5SHA1';
MD5SHA1.size = 36;
MD5SHA1.bits = 288;
MD5SHA1.blockSize = 64;
MD5SHA1.zero = Buffer.alloc(36, 0x00);
MD5SHA1.ctx = new MD5SHA1();

/*
 * Expose
 */

module.exports = MD5SHA1;
