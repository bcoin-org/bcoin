/*!
 * hash256.js - Hash256 implementation for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://github.com/bitcoin/bitcoin/blob/master/src/hash.h
 */

'use strict';

const assert = require('../internal/assert');
const SHA256 = require('./sha256');
const HMAC = require('../internal/hmac');

/**
 * Hash256
 */

class Hash256 {
  constructor() {
    this.ctx = new SHA256();
  }

  init() {
    this.ctx.init();
    return this;
  }

  update(data) {
    this.ctx.update(data);
    return this;
  }

  final() {
    const out = Buffer.alloc(32);

    this.ctx._final(out);
    this.ctx.init();
    this.ctx.update(out);
    this.ctx._final(out);

    return out;
  }

  static hash() {
    return new Hash256();
  }

  static hmac() {
    return new HMAC(Hash256, 64);
  }

  static digest(data) {
    return Hash256.ctx.init().update(data).final();
  }

  static root(left, right) {
    assert(Buffer.isBuffer(left) && left.length === 32);
    assert(Buffer.isBuffer(right) && right.length === 32);
    return Hash256.ctx.init().update(left).update(right).final();
  }

  static multi(x, y, z) {
    const {ctx} = Hash256;

    ctx.init();
    ctx.update(x);
    ctx.update(y);

    if (z)
      ctx.update(z);

    return ctx.final();
  }

  static mac(data, key) {
    return Hash256.hmac().init(key).update(data).final();
  }
}

/*
 * Static
 */

Hash256.native = 0;
Hash256.id = 'HASH256';
Hash256.size = 32;
Hash256.bits = 256;
Hash256.blockSize = 64;
Hash256.zero = Buffer.alloc(32, 0x00);
Hash256.ctx = new Hash256();

/*
 * Expose
 */

module.exports = Hash256;
