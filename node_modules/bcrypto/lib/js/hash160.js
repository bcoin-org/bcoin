/*!
 * hash160.js - Hash160 implementation for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://github.com/bitcoin/bitcoin/blob/master/src/hash.h
 */

'use strict';

const assert = require('../internal/assert');
const SHA256 = require('./sha256');
const RIPEMD160 = require('./ripemd160');
const HMAC = require('../internal/hmac');

/*
 * Constants
 */

const rmd = new RIPEMD160();

/**
 * Hash160
 */

class Hash160 {
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

    rmd.init();
    rmd.update(out);
    rmd._final(out);

    return out.slice(0, 20);
  }

  static hash() {
    return new Hash160();
  }

  static hmac() {
    return new HMAC(Hash160, 64);
  }

  static digest(data) {
    return Hash160.ctx.init().update(data).final();
  }

  static root(left, right) {
    assert(Buffer.isBuffer(left) && left.length === 20);
    assert(Buffer.isBuffer(right) && right.length === 20);
    return Hash160.ctx.init().update(left).update(right).final();
  }

  static multi(x, y, z) {
    const {ctx} = Hash160;

    ctx.init();
    ctx.update(x);
    ctx.update(y);

    if (z)
      ctx.update(z);

    return ctx.final();
  }

  static mac(data, key) {
    return Hash160.hmac().init(key).update(data).final();
  }
}

/*
 * Static
 */

Hash160.native = 0;
Hash160.id = 'HASH160';
Hash160.size = 20;
Hash160.bits = 160;
Hash160.blockSize = 64;
Hash160.zero = Buffer.alloc(20, 0x00);
Hash160.ctx = new Hash160();

/*
 * Expose
 */

module.exports = Hash160;
