/*!
 * md4.js - MD4 implementation for bcrypto
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const crypto = require('crypto');
const HMAC = require('../internal/hmac');

/**
 * MD4
 */

class MD4 {
  constructor() {
    this.ctx = null;
  }

  init() {
    this.ctx = crypto.createHash('md4');
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
    return new MD4();
  }

  static hmac() {
    return new HMAC(MD4, 64);
  }

  static digest(data) {
    return MD4.ctx.init().update(data).final();
  }

  static root(left, right) {
    assert(Buffer.isBuffer(left) && left.length === 16);
    assert(Buffer.isBuffer(right) && right.length === 16);
    return MD4.ctx.init().update(left).update(right).final();
  }

  static multi(x, y, z) {
    const ctx = MD4.ctx;
    ctx.init();
    ctx.update(x);
    ctx.update(y);
    if (z)
      ctx.update(z);
    return ctx.final();
  }

  static mac(data, key) {
    return MD4.hmac().init(key).update(data).final();
  }
}

MD4.native = 1;
MD4.id = 'MD4';
MD4.size = 16;
MD4.bits = 128;
MD4.blockSize = 64;
MD4.zero = Buffer.alloc(16, 0x00);
MD4.ctx = new MD4();

/*
 * Expose
 */

module.exports = MD4;
