/*!
 * sha384.js - SHA384 implementation for bcrypto
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const crypto = require('crypto');
const HMAC = require('../internal/hmac');

/**
 * SHA384
 */

class SHA384 {
  constructor() {
    this.ctx = null;
  }

  init() {
    this.ctx = crypto.createHash('sha384');
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
    return new SHA384();
  }

  static hmac() {
    return new HMAC(SHA384, 128);
  }

  static digest(data) {
    return SHA384.ctx.init().update(data).final();
  }

  static root(left, right) {
    assert(Buffer.isBuffer(left) && left.length === 48);
    assert(Buffer.isBuffer(right) && right.length === 48);
    return SHA384.ctx.init().update(left).update(right).final();
  }

  static multi(x, y, z) {
    const ctx = SHA384.ctx;
    ctx.init();
    ctx.update(x);
    ctx.update(y);
    if (z)
      ctx.update(z);
    return ctx.final();
  }

  static mac(data, key) {
    return SHA384.hmac().init(key).update(data).final();
  }
}

SHA384.native = 1;
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
