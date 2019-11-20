/*!
 * blake2b.js - BLAKE2b implementation for bcrypto
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const crypto = require('crypto');
const Backend = require('../js/blake2b');
const HMAC = require('../internal/hmac');
const hashes = crypto.getHashes();

/*
 * Constants
 */

const names = {
  20: hashes.indexOf('blake2b160') !== -1
    ? 'blake2b160'
    : null,
  32: hashes.indexOf('blake2b256') !== -1
    ? 'blake2b256'
    : null,
  48: hashes.indexOf('blake2b384') !== -1
    ? 'blake2b384'
    : null,
  64: hashes.indexOf('blake2b512') !== -1
    ? 'blake2b512'
    : null
};

/**
 * BLAKE2b
 */

class BLAKE2b {
  /**
   * Create a BLAKE2b context.
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
    return new BLAKE2b();
  }

  static hmac(size = 32) {
    return new HMAC(BLAKE2b, 128, [size]);
  }

  static digest(data, size = 32, key = null) {
    const ctx = BLAKE2b.ctx;
    ctx.init(size, key);
    ctx.update(data);
    return ctx.final();
  }

  static root(left, right, size = 32) {
    assert(Buffer.isBuffer(left) && left.length === size);
    assert(Buffer.isBuffer(right) && right.length === size);
    const ctx = BLAKE2b.ctx;
    ctx.init(size);
    ctx.update(left);
    ctx.update(right);
    return ctx.final();
  }

  static multi(x, y, z, size = 32) {
    const ctx = BLAKE2b.ctx;
    ctx.init(size);
    ctx.update(x);
    ctx.update(y);
    if (z)
      ctx.update(z);
    return ctx.final();
  }

  static mac(data, key, size = 32) {
    return BLAKE2b.hmac(size).init(key).update(data).final();
  }
}

BLAKE2b.native = 1;
BLAKE2b.id = 'BLAKE2B256';
BLAKE2b.size = 32;
BLAKE2b.bits = 256;
BLAKE2b.blockSize = 128;
BLAKE2b.zero = Buffer.alloc(32, 0x00);
BLAKE2b.ctx = new BLAKE2b();

/*
 * Expose
 */

module.exports = BLAKE2b;
