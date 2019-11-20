/*!
 * sha1.js - SHA1 implementation for bcrypto
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const crypto = require('crypto');
const HMAC = require('../internal/hmac');

/**
 * SHA1
 */

class SHA1 {
  constructor() {
    this.ctx = null;
  }

  init() {
    this.ctx = crypto.createHash('sha1');
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
    return new SHA1();
  }

  static hmac() {
    return new HMAC(SHA1, 64);
  }

  static digest(data) {
    return SHA1.ctx.init().update(data).final();
  }

  static root(left, right) {
    assert(Buffer.isBuffer(left) && left.length === 20);
    assert(Buffer.isBuffer(right) && right.length === 20);
    return SHA1.ctx.init().update(left).update(right).final();
  }

  static multi(x, y, z) {
    const ctx = SHA1.ctx;
    ctx.init();
    ctx.update(x);
    ctx.update(y);
    if (z)
      ctx.update(z);
    return ctx.final();
  }

  static mac(data, key) {
    return SHA1.hmac().init(key).update(data).final();
  }
}

SHA1.native = 1;
SHA1.id = 'SHA1';
SHA1.size = 20;
SHA1.bits = 160;
SHA1.blockSize = 64;
SHA1.zero = Buffer.alloc(20, 0x00);
SHA1.ctx = new SHA1();

/*
 * Expose
 */

module.exports = SHA1;
