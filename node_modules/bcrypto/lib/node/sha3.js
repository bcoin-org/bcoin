/*!
 * sha3.js - SHA3 implementation for bcrypto
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const crypto = require('crypto');
const Backend = require('../js/sha3');
const HMAC = require('../internal/hmac');
const hashes = crypto.getHashes();

/*
 * Constants
 */

const names = {
  224: hashes.indexOf('sha3-224') !== -1
    ? 'sha3-224'
    : null,
  256: hashes.indexOf('sha3-256') !== -1
    ? 'sha3-256'
    : null,
  384: hashes.indexOf('sha3-384') !== -1
    ? 'sha3-384'
    : null,
  512: hashes.indexOf('sha3-512') !== -1
    ? 'sha3-512'
    : null
};

/**
 * SHA3
 */

class SHA3 {
  /**
   * Create a SHA3 Context.
   * @constructor
   */

  constructor() {
    this.node = null;
    this.js = null;
  }

  init(bits = 256) {
    assert((bits & 0xffff) === bits);

    if (typeof names[bits] === 'string') {
      this.node = crypto.createHash(names[bits]);
      this.js = null;
    } else {
      this.node = null;
      this.js = new Backend();
      this.js.init(bits);
    }

    return this;
  }

  update(data) {
    if (this.node) {
      assert(Buffer.isBuffer(data));
      this.node.update(data);
    } else {
      assert(this.js);
      this.js.update(data);
    }
    return this;
  }

  final() {
    let ret;

    if (this.node) {
      ret = this.node.digest();
      this.node = null;
    } else {
      assert(this.js);
      ret = this.js.final();
      this.js = null;
    }

    return ret;
  }

  static hash() {
    return new SHA3();
  }

  static hmac(bits = 256) {
    assert((bits >>> 0) === bits);
    const bs = (1600 - bits * 2) / 8;
    return new HMAC(SHA3, bs, [bits]);
  }

  static digest(data, bits = 256) {
    return SHA3.ctx.init(bits).update(data).final();
  }

  static root(left, right, bits = 256) {
    assert(Buffer.isBuffer(left) && left.length === bits / 8);
    assert(Buffer.isBuffer(right) && right.length === bits / 8);
    return SHA3.ctx.init(bits).update(left).update(right).final();
  }

  static multi(x, y, z, bits = 256) {
    const ctx = SHA3.ctx;
    ctx.init(bits);
    ctx.update(x);
    ctx.update(y);
    if (z)
      ctx.update(z);
    return ctx.final();
  }

  static mac(data, key, bits = 256) {
    return SHA3.hmac(bits).init(key).update(data).final();
  }
}

SHA3.native = 1;
SHA3.id = 'SHA3_256';
SHA3.size = 32;
SHA3.bits = 256;
SHA3.blockSize = 136;
SHA3.zero = Buffer.alloc(32, 0x00);
SHA3.ctx = new SHA3();

/*
 * Expose
 */

module.exports = SHA3;
