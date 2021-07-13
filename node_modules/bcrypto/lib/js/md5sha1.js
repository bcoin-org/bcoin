/*!
 * md5sha1.js - MD5-SHA1 implementation for bcrypto
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('../internal/assert');
const MD5 = require('./md5');
const SHA1 = require('./sha1');
const HMAC = require('../internal/hmac');

/**
 * MD5SHA1
 */

class MD5SHA1 {
  constructor() {
    this.md5 = new MD5();
    this.sha1 = new SHA1();
  }

  init() {
    this.md5.init();
    this.sha1.init();
    return this;
  }

  update(data) {
    this.md5.update(data);
    this.sha1.update(data);
    return this;
  }

  final() {
    const md = Buffer.alloc(36);

    this.md5.final().copy(md, 0);
    this.sha1.final().copy(md, 16);

    return md;
  }

  static hash() {
    return new MD5SHA1();
  }

  static hmac() {
    return new HMAC(MD5SHA1, 64);
  }

  static digest(data) {
    return MD5SHA1.ctx.init().update(data).final();
  }

  static root(left, right) {
    assert(Buffer.isBuffer(left) && left.length === 36);
    assert(Buffer.isBuffer(right) && right.length === 36);
    return MD5SHA1.ctx.init().update(left).update(right).final();
  }

  static multi(x, y, z) {
    const {ctx} = MD5SHA1;

    ctx.init();
    ctx.update(x);
    ctx.update(y);

    if (z)
      ctx.update(z);

    return ctx.final();
  }

  static mac(data, key) {
    return MD5SHA1.hmac().init(key).update(data).final();
  }
}

/*
 * Static
 */

MD5SHA1.native = 0;
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
