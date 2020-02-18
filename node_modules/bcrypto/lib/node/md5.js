/*!
 * md5.js - MD5 implementation for bcrypto
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const crypto = require('crypto');
const HMAC = require('../internal/hmac');

/**
 * MD5
 */

class MD5 {
  constructor() {
    this.ctx = null;
  }

  init() {
    this.ctx = crypto.createHash('md5');
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
    return new MD5();
  }

  static hmac() {
    return new HMAC(MD5, 64);
  }

  static digest(data) {
    return MD5.ctx.init().update(data).final();
  }

  static root(left, right) {
    assert(Buffer.isBuffer(left) && left.length === 16);
    assert(Buffer.isBuffer(right) && right.length === 16);
    return MD5.ctx.init().update(left).update(right).final();
  }

  static multi(x, y, z) {
    const ctx = MD5.ctx;
    ctx.init();
    ctx.update(x);
    ctx.update(y);
    if (z)
      ctx.update(z);
    return ctx.final();
  }

  static mac(data, key) {
    return MD5.hmac().init(key).update(data).final();
  }
}

MD5.native = 1;
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
