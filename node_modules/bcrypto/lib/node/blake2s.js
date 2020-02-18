/*!
 * blake2s.js - BLAKE2s implementation for bcrypto
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const crypto = require('crypto');
const Backend = require('../js/blake2s');
const HMAC = require('../internal/hmac');
const hashes = crypto.getHashes();

/*
 * Constants
 */

const names = {
  16: hashes.indexOf('blake2s128') !== -1
    ? 'blake2s128'
    : null,
  20: hashes.indexOf('blake2s160') !== -1
    ? 'blake2s160'
    : null,
  28: hashes.indexOf('blake2s224') !== -1
    ? 'blake2s224'
    : null,
  32: hashes.indexOf('blake2s256') !== -1
    ? 'blake2s256'
    : null
};

/**
 * BLAKE2s
 */

class BLAKE2s {
  /**
   * Create a BLAKE2s context.
   * @constructor
   */

  constructor() {
    this.node = null;
    this.js = null;
  }

  init(size = 32, key = null) {
    assert((size >>> 0) === size);

    if (key && key.length === 0)
      key = null;

    if (!key && typeof names[size] === 'string') {
      this.node = crypto.createHash(names[size]);
      this.js = null;
    } else {
      this.node = null;
      this.js = new Backend();
      this.js.init(size, key);
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
    return new BLAKE2s();
  }

  static hmac(size = 32) {
    return new HMAC(BLAKE2s, 64, [size]);
  }

  static digest(data, size = 32, key = null) {
    const ctx = BLAKE2s.ctx;
    ctx.init(size, key);
    ctx.update(data);
    return ctx.final();
  }

  static root(left, right, size = 32) {
    assert(Buffer.isBuffer(left) && left.length === size);
    assert(Buffer.isBuffer(right) && right.length === size);
    const ctx = BLAKE2s.ctx;
    ctx.init(size);
    ctx.update(left);
    ctx.update(right);
    return ctx.final();
  }

  static multi(x, y, z, size = 32) {
    const ctx = BLAKE2s.ctx;
    ctx.init(size);
    ctx.update(x);
    ctx.update(y);
    if (z)
      ctx.update(z);
    return ctx.final();
  }

  static mac(data, key, size = 32) {
    return BLAKE2s.hmac(size).init(key).update(data).final();
  }
}

BLAKE2s.native = 1;
BLAKE2s.id = 'BLAKE2S256';
BLAKE2s.size = 32;
BLAKE2s.bits = 256;
BLAKE2s.blockSize = 64;
BLAKE2s.zero = Buffer.alloc(32, 0x00);
BLAKE2s.ctx = new BLAKE2s();

/*
 * Expose
 */

module.exports = BLAKE2s;
