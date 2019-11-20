/*!
 * sha224.js - SHA224 implementation for bcrypto
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const crypto = require('crypto');
const HMAC = require('../internal/hmac');

/**
 * SHA224
 */

class SHA224 {
  constructor() {
    this.ctx = null;
  }

  init() {
    this.ctx = crypto.createHash('sha224');
    return this;
  }

  update(data) {
    assert(Buffer.isBuffer(data));
    assert(this.ctx, 'Context already finalized.');
    this.ctx.update(data);
    return this;
  }

  final() {
    assert(this.ctx, 'Context already finalized.');
    const hash = this.ctx.digest();
    this.ctx = null;
    return hash;
  }

  static hash() {
    return new SHA224();
  }

  static hmac() {
    return new HMAC(SHA224, 64);
  }

  static digest(data) {
    return SHA224.ctx.init().update(data).final();
  }

  static root(left, right) {
    assert(Buffer.isBuffer(left) && left.length === 28);
    assert(Buffer.isBuffer(right) && right.length === 28);
    return SHA224.ctx.init().update(left).update(right).final();
  }

  static multi(x, y, z) {
    const ctx = SHA224.ctx;
    ctx.init();
    ctx.update(x);
    ctx.update(y);
    if (z)
      ctx.update(z);
    return ctx.final();
  }

  static mac(data, key) {
    return SHA224.hmac().init(key).update(data).final();
  }
}

SHA224.native = 1;
SHA224.id = 'SHA224';
SHA224.size = 28;
SHA224.bits = 224;
SHA224.blockSize = 64;
SHA224.zero = Buffer.alloc(28, 0x00);
SHA224.ctx = new SHA224();

/*
 * Expose
 */

module.exports = SHA224;
