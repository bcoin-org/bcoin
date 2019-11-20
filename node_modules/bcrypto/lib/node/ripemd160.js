/*!
 * ripemd160.js - RIPEMD160 implementation for bcrypto
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const crypto = require('crypto');
const HMAC = require('../internal/hmac');

/**
 * RIPEMD160
 */

class RIPEMD160 {
  constructor() {
    this.ctx = null;
  }

  init() {
    this.ctx = crypto.createHash('ripemd160');
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
    return new RIPEMD160();
  }

  static hmac() {
    return new HMAC(RIPEMD160, 64);
  }

  static digest(data) {
    return RIPEMD160.ctx.init().update(data).final();
  }

  static root(left, right) {
    assert(Buffer.isBuffer(left) && left.length === 20);
    assert(Buffer.isBuffer(right) && right.length === 20);
    return RIPEMD160.ctx.init().update(left).update(right).final();
  }

  static multi(x, y, z) {
    const ctx = RIPEMD160.ctx;
    ctx.init();
    ctx.update(x);
    ctx.update(y);
    if (z)
      ctx.update(z);
    return ctx.final();
  }

  static mac(data, key) {
    return RIPEMD160.hmac().init(key).update(data).final();
  }
}

RIPEMD160.native = 1;
RIPEMD160.id = 'RIPEMD160';
RIPEMD160.size = 20;
RIPEMD160.bits = 160;
RIPEMD160.blockSize = 64;
RIPEMD160.zero = Buffer.alloc(20, 0x00);
RIPEMD160.ctx = new RIPEMD160();

/*
 * Expose
 */

module.exports = RIPEMD160;
