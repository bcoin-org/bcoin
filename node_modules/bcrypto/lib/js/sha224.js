/*!
 * sha224.js - SHA224 implementation for bcrypto
 * Copyright (c) 2016-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 * Parts of this software based on hash.js.
 */

'use strict';

const assert = require('bsert');
const SHA256 = require('./sha256');
const HMAC = require('../internal/hmac');

/**
 * SHA224
 */

class SHA224 extends SHA256 {
  /**
   * Create a SHA256 context.
   * @constructor
   */

  constructor() {
    super();
  }

  /**
   * Initialize SHA224 context.
   */

  init() {
    this.state[0] = 0xc1059ed8;
    this.state[1] = 0x367cd507;
    this.state[2] = 0x3070dd17;
    this.state[3] = 0xf70e5939;
    this.state[4] = 0xffc00b31;
    this.state[5] = 0x68581511;
    this.state[6] = 0x64f98fa7;
    this.state[7] = 0xbefa4fa4;
    this.size = 0;
    return this;
  }

  /**
   * Finalize SHA224 context.
   * @returns {Buffer}
   */

  final() {
    return super.final().slice(0, 28);
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

SHA224.native = 0;
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
