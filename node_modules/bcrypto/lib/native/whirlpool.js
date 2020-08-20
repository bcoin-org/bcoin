/*!
 * whirlpool.js - whirlpool implementation for bcrypto
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const {Hash, HMAC, hashes} = require('./hash');

/*
 * Whirlpool
 */

class Whirlpool extends Hash {
  constructor() {
    super(hashes.WHIRLPOOL);
  }

  static hash() {
    return new Whirlpool();
  }

  static hmac() {
    return new HMAC(hashes.WHIRLPOOL);
  }

  static digest(data) {
    return Hash.digest(hashes.WHIRLPOOL, data);
  }

  static root(left, right) {
    return Hash.root(hashes.WHIRLPOOL, left, right);
  }

  static multi(x, y, z) {
    return Hash.multi(hashes.WHIRLPOOL, x, y, z);
  }

  static mac(data, key) {
    return HMAC.digest(hashes.WHIRLPOOL, data, key);
  }
}

/*
 * Static
 */

Whirlpool.native = 2;
Whirlpool.id = 'WHIRLPOOL';
Whirlpool.size = 64;
Whirlpool.bits = 512;
Whirlpool.blockSize = 64;
Whirlpool.zero = Buffer.alloc(64, 0x00);
Whirlpool.ctx = new Whirlpool();

/*
 * Expose
 */

module.exports = Whirlpool;
