/*!
 * sha1.js - SHA1 implementation for bcrypto
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 * Parts of this software based on hash.js.
 */

/* eslint camelcase: "off" */

'use strict';

const assert = require('bsert');
const HMAC = require('../internal/hmac');

/*
 * Constants
 */

const FINALIZED = -1;
const DESC = Buffer.alloc(8, 0x00);
const PADDING = Buffer.alloc(64, 0x00);

PADDING[0] = 0x80;

const K = new Uint32Array([
  0x5a827999,
  0x6ed9eba1,
  0x8f1bbcdc,
  0xca62c1d6
]);

/**
 * SHA1
 */

class SHA1 {
  /**
   * Create a SHA1 context.
   * @constructor
   */

  constructor() {
    this.state = new Uint32Array(5);
    this.msg = new Uint32Array(80);
    this.block = Buffer.allocUnsafe(64);
    this.size = FINALIZED;
  }

  /**
   * Initialize SHA1 context.
   * @returns {SHA1}
   */

  init() {
    this.state[0] = 0x67452301;
    this.state[1] = 0xefcdab89;
    this.state[2] = 0x98badcfe;
    this.state[3] = 0x10325476;
    this.state[4] = 0xc3d2e1f0;
    this.size = 0;
    return this;
  }

  /**
   * Update SHA1 context.
   * @param {Buffer} data
   * @returns {SHA1}
   */

  update(data) {
    assert(Buffer.isBuffer(data));
    this._update(data, data.length);
    return this;
  }

  /**
   * Finalize SHA1 context.
   * @returns {Buffer}
   */

  final() {
    return this._final(Buffer.allocUnsafe(20));
  }

  /**
   * Update SHA1 context.
   * @private
   * @param {Buffer} data
   * @param {Number} len
   */

  _update(data, len) {
    assert(this.size !== FINALIZED, 'Context already finalized.');

    let pos = this.size & 0x3f;
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

      this.transform(this.block, 0);
    }

    while (len >= 64) {
      this.transform(data, off);
      off += 64;
      len -= 64;
    }

    if (len > 0)
      data.copy(this.block, 0, off, off + len);
  }

  /**
   * Finalize SHA1 context.
   * @private
   * @param {Buffer} out
   * @returns {Buffer}
   */

  _final(out) {
    assert(this.size !== FINALIZED, 'Context already finalized.');

    const pos = this.size % 64;
    const len = this.size * 8;

    writeU32(DESC, len * (1 / 0x100000000), 0);
    writeU32(DESC, len, 4);

    this._update(PADDING, 1 + ((119 - pos) % 64));
    this._update(DESC, 8);

    for (let i = 0; i < 5; i++) {
      writeU32(out, this.state[i], i * 4);
      this.state[i] = 0;
    }

    for (let i = 0; i < 80; i++)
      this.msg[i] = 0;

    for (let i = 0; i < 64; i++)
      this.block[i] = 0;

    this.size = FINALIZED;

    return out;
  }

  /**
   * Transform SHA1 block.
   * @param {Buffer} chunk
   * @param {Number} pos
   */

  transform(chunk, pos) {
    const W = this.msg;

    let a = this.state[0];
    let b = this.state[1];
    let c = this.state[2];
    let d = this.state[3];
    let e = this.state[4];
    let i = 0;

    for (; i < 16; i++)
      W[i] = readU32(chunk, pos + i * 4);

    for (; i < 80; i++)
      W[i] = rotl32(W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16], 1);

    for (i = 0; i < 80; i++) {
      const s = i / 20 | 0;

      let t = rotl32(a, 5);
      t += ft_1(s, b, c, d);
      t += e;
      t += W[i];
      t += K[s];

      e = d;
      d = c;
      c = rotl32(b, 30);
      b = a;
      a = t;
    }

    this.state[0] += a;
    this.state[1] += b;
    this.state[2] += c;
    this.state[3] += d;
    this.state[4] += e;
  }

  static hash() {
    return new SHA1();
  }

  static hmac() {
    return new HMAC(SHA1, 64);
  }

  static digest(data) {
    return SHA1.ctx.init().update(data).final();
  }

  static root(left, right) {
    assert(Buffer.isBuffer(left) && left.length === 20);
    assert(Buffer.isBuffer(right) && right.length === 20);
    return SHA1.ctx.init().update(left).update(right).final();
  }

  static multi(x, y, z) {
    const ctx = SHA1.ctx;
    ctx.init();
    ctx.update(x);
    ctx.update(y);
    if (z)
      ctx.update(z);
    return ctx.final();
  }

  static mac(data, key) {
    return SHA1.hmac().init(key).update(data).final();
  }
}

SHA1.native = 0;
SHA1.id = 'SHA1';
SHA1.size = 20;
SHA1.bits = 160;
SHA1.blockSize = 64;
SHA1.zero = Buffer.alloc(20, 0x00);
SHA1.ctx = new SHA1();

/*
 * Helpers
 */

function rotl32(w, b) {
  return (w << b) | (w >>> (32 - b));
}

function ft_1(s, x, y, z) {
  if (s === 0)
    return ch32(x, y, z);

  if (s === 1 || s === 3)
    return p32(x, y, z);

  if (s === 2)
    return maj32(x, y, z);

  return 0;
}

function ch32(x, y, z) {
  return (x & y) ^ ((~x) & z);
}

function maj32(x, y, z) {
  return (x & y) ^ (x & z) ^ (y & z);
}

function p32(x, y, z) {
  return x ^ y ^ z;
}

function writeU32(buf, value, offset) {
  buf[offset] = value >>> 24;
  buf[offset + 1] = (value >> 16) & 0xff;
  buf[offset + 2] = (value >> 8) & 0xff;
  buf[offset + 3] = value & 0xff;
}

function readU32(buf, offset) {
  return ((buf[offset] & 0xff) * 0x1000000)
    + (((buf[offset + 1] & 0xff) << 16)
    | ((buf[offset + 2] & 0xff) << 8)
    | (buf[offset + 3] & 0xff));
}

/*
 * Expose
 */

module.exports = SHA1;
