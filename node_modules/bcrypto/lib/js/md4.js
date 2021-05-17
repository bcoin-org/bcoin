/*!
 * md4.js - MD4 implementation for bcrypto
 * Copyright (c) 2016-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on RustCrypto/hashes:
 *   Copyright (c) 2016-2018, The RustCrypto Authors (MIT License).
 *   https://github.com/RustCrypto/hashes
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/MD4
 *   https://tools.ietf.org/html/rfc1320
 *   https://github.com/RustCrypto/hashes/blob/master/md4/src/lib.rs
 */

'use strict';

const assert = require('../internal/assert');
const HMAC = require('../internal/hmac');

/*
 * Constants
 */

const FINALIZED = -1;
const DESC = Buffer.alloc(8, 0x00);
const PADDING = Buffer.alloc(64, 0x00);

PADDING[0] = 0x80;

const K = new Uint32Array([
  0x67452301, 0xefcdab89,
  0x98badcfe, 0x10325476
]);

/**
 * MD4
 */

class MD4 {
  constructor() {
    this.state = new Uint32Array(4);
    this.msg = new Uint32Array(16);
    this.block = Buffer.alloc(64);
    this.size = FINALIZED;
  }

  init() {
    this.state[0] = K[0];
    this.state[1] = K[1];
    this.state[2] = K[2];
    this.state[3] = K[3];
    this.size = 0;
    return this;
  }

  update(data) {
    assert(Buffer.isBuffer(data));
    this._update(data, data.length);
    return this;
  }

  final() {
    return this._final(Buffer.alloc(16));
  }

  _update(data, len) {
    assert(this.size !== FINALIZED, 'Context is not initialized.');

    let pos = this.size & 63;
    let off = 0;

    this.size += len;

    if (pos > 0) {
      let want = 64 - pos;

      if (want > len)
        want = len;

      data.copy(this.block, pos, off, off + want);

      pos += want;
      len -= want;
      off += want;

      if (pos < 64)
        return;

      this._transform(this.block, 0);
    }

    while (len >= 64) {
      this._transform(data, off);
      off += 64;
      len -= 64;
    }

    if (len > 0)
      data.copy(this.block, 0, off, off + len);
  }

  /**
   * Finalize MD4 context.
   * @private
   * @param {Buffer} out
   * @returns {Buffer}
   */

  _final(out) {
    assert(this.size !== FINALIZED, 'Context is not initialized.');

    const pos = this.size & 63;
    const len = this.size * 8;

    writeU32(DESC, len >>> 0, 0);
    writeU32(DESC, (len * (1 / 0x100000000)) >>> 0, 4);

    this._update(PADDING, 1 + ((119 - pos) & 63));
    this._update(DESC, 8);

    for (let i = 0; i < 4; i++) {
      writeU32(out, this.state[i], i * 4);
      this.state[i] = 0;
    }

    for (let i = 0; i < 16; i++)
      this.msg[i] = 0;

    for (let i = 0; i < 64; i++)
      this.block[i] = 0;

    this.size = FINALIZED;

    return out;
  }

  _transform(chunk, pos) {
    const W = this.msg;

    let a = this.state[0];
    let b = this.state[1];
    let c = this.state[2];
    let d = this.state[3];

    for (let i = 0; i < 16; i++)
      W[i] = readU32(chunk, pos + i * 4);

    // round 1
    for (const i of [0, 4, 8, 12]) {
      a = op1(a, b, c, d, W[i], 3);
      d = op1(d, a, b, c, W[i + 1], 7);
      c = op1(c, d, a, b, W[i + 2], 11);
      b = op1(b, c, d, a, W[i + 3], 19);
    }

    // round 2
    for (let i = 0; i < 4; i++) {
      a = op2(a, b, c, d, W[i], 3);
      d = op2(d, a, b, c, W[i + 4], 5);
      c = op2(c, d, a, b, W[i + 8], 9);
      b = op2(b, c, d, a, W[i + 12], 13);
    }

    // round 3
    for (const i of [0, 2, 1, 3]) {
      a = op3(a, b, c, d, W[i], 3);
      d = op3(d, a, b, c, W[i + 8], 9);
      c = op3(c, d, a, b, W[i + 4], 11);
      b = op3(b, c, d, a, W[i + 12], 15);
    }

    this.state[0] += a;
    this.state[1] += b;
    this.state[2] += c;
    this.state[3] += d;
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
    const {ctx} = MD4;

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

/*
 * Static
 */

MD4.native = 0;
MD4.id = 'MD4';
MD4.size = 16;
MD4.bits = 128;
MD4.blockSize = 64;
MD4.zero = Buffer.alloc(16, 0x00);
MD4.ctx = new MD4();

/*
 * Helpers
 */

function f(x, y, z) {
  return (x & y) | (~x & z);
}

function g(x, y, z) {
  return (x & y) | (x & z) | (y & z);
}

function h(x, y, z) {
  return x ^ y ^ z;
}

function op1(a, b, c, d, k, s) {
  return rotl32(a + f(b, c, d) + k, s);
}

function op2(a, b, c, d, k, s) {
  return rotl32(a + g(b, c, d) + k + 0x5a827999, s);
}

function op3(a, b, c, d, k, s) {
  return rotl32(a + h(b, c, d) + k + 0x6ed9eba1, s);
}

function rotl32(w, b) {
  return (w << b) | (w >>> (32 - b));
}

function readU32(data, off) {
  return (data[off++]
        + data[off++] * 0x100
        + data[off++] * 0x10000
        + data[off] * 0x1000000);
}

function writeU32(dst, num, off) {
  dst[off++] = num;
  num >>>= 8;
  dst[off++] = num;
  num >>>= 8;
  dst[off++] = num;
  num >>>= 8;
  dst[off++] = num;
  return off;
}

/*
 * Expose
 */

module.exports = MD4;
