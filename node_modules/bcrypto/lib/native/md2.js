/*!
 * md2.js - MD2 implementation for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const {Hash, HMAC, hashes} = require('./hash');

/*
 * MD2
 */

class MD2 extends Hash {
  constructor() {
    super(hashes.MD2);
  }

  static hash() {
    return new MD2();
  }

  static hmac() {
    return new HMAC(hashes.MD2);
  }

  static digest(data) {
    return Hash.digest(hashes.MD2, data);
  }

  static root(left, right) {
    return Hash.root(hashes.MD2, left, right);
  }

  static multi(x, y, z) {
    return Hash.multi(hashes.MD2, x, y, z);
  }

  static mac(data, key) {
    return HMAC.digest(hashes.MD2, data, key);
  }
}

/*
 * Static
 */

MD2.native = 2;
MD2.id = 'MD2';
MD2.size = 16;
MD2.bits = 128;
MD2.blockSize = 16;
MD2.zero = Buffer.alloc(16, 0x00);
MD2.ctx = new MD2();

/*
 * Expose
 */

module.exports = MD2;
