/*!
 * gost94.js - GOST94 implementation for bcrypto
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on RustCrypto/hashes:
 *   Copyright (c) 2016-2018, The RustCrypto Authors (MIT License).
 *   https://github.com/RustCrypto/hashes
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/GOST_(hash_function)
 *   https://tools.ietf.org/html/rfc4357
 *   https://tools.ietf.org/html/rfc5831
 *   https://github.com/RustCrypto/hashes/blob/master/gost94/src/gost94.rs
 */

'use strict';

const assert = require('../internal/assert');
const HMAC = require('../internal/hmac');

/*
 * Constants
 */

const FINALIZED = -1;
const PADDING = Buffer.alloc(32, 0x00);
const DESC = Buffer.alloc(32, 0x00);

const C = Buffer.from([
  0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff,
  0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00,
  0x00, 0xff, 0xff, 0x00, 0xff, 0x00, 0x00, 0xff,
  0xff, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0xff
]);

const S_CRYPTOPRO = [
  Buffer.from([10, 4, 5, 6, 8, 1, 3, 7, 13, 12, 14, 0, 9, 2, 11, 15]),
  Buffer.from([5, 15, 4, 0, 2, 13, 11, 9, 1, 7, 6, 3, 12, 14, 10, 8]),
  Buffer.from([7, 15, 12, 14, 9, 4, 1, 0, 3, 11, 5, 2, 6, 10, 8, 13]),
  Buffer.from([4, 10, 7, 12, 0, 15, 2, 8, 14, 1, 6, 5, 13, 11, 9, 3]),
  Buffer.from([7, 6, 4, 11, 9, 12, 2, 10, 1, 8, 0, 14, 15, 13, 3, 5]),
  Buffer.from([7, 6, 2, 4, 13, 9, 15, 0, 10, 1, 5, 11, 8, 14, 12, 3]),
  Buffer.from([13, 14, 4, 1, 7, 0, 5, 10, 3, 12, 8, 15, 6, 2, 9, 11]),
  Buffer.from([1, 3, 10, 9, 5, 11, 4, 15, 8, 6, 7, 14, 13, 0, 2, 12])
];

const S_TEST = [
  Buffer.from([4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3]),
  Buffer.from([14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9]),
  Buffer.from([5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11]),
  Buffer.from([7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3]),
  Buffer.from([6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2]),
  Buffer.from([4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14]),
  Buffer.from([13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12]),
  Buffer.from([1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12])
];

const S_S2015 = [
  Buffer.from([12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1]),
  Buffer.from([6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15]),
  Buffer.from([11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0]),
  Buffer.from([12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11]),
  Buffer.from([7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12]),
  Buffer.from([5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0]),
  Buffer.from([8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7]),
  Buffer.from([1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2])
];

/**
 * GOST94
 */

class GOST94 {
  constructor() {
    this.S = S_CRYPTOPRO;
    this.state = Buffer.alloc(32);
    this.sigma = Buffer.alloc(32);
    this.block = Buffer.alloc(32);
    this.size = FINALIZED;
  }

  init(box) {
    if (box == null)
      box = S_CRYPTOPRO;

    assert(Array.isArray(box) && box.length === 8);

    this.S = box;
    this.state.fill(0);
    this.sigma.fill(0);
    this.size = 0;

    return this;
  }

  update(data) {
    assert(Buffer.isBuffer(data));
    this._update(data, data.length);
    return this;
  }

  final() {
    return this._final(Buffer.alloc(32));
  }

  _update(data, len) {
    assert(this.size !== FINALIZED, 'Context is not initialized.');

    let pos = this.size & 31;
    let off = 0;

    this.size += len;

    if (pos > 0) {
      let want = 32 - pos;

      if (want > len)
        want = len;

      data.copy(this.block, pos, off, off + want);

      pos += want;
      len -= want;
      off += want;

      if (pos < 32)
        return;

      this._transform(this.block, 0);
    }

    while (len >= 32) {
      this._transform(data, off);
      off += 32;
      len -= 32;
    }

    if (len > 0)
      data.copy(this.block, 0, off, off + len);
  }

  _final(out) {
    assert(this.size !== FINALIZED, 'Context is not initialized.');

    const bits = this.size * 8;
    const pos = this.size & 31;

    if (pos !== 0)
      this._update(PADDING, 32 - pos);

    const hi = (bits * (1 / 0x100000000)) >>> 0;
    const lo = bits >>> 0;

    writeU32(DESC, lo, 0);
    writeU32(DESC, hi, 4);

    this._f(DESC);
    this._f(this.sigma);

    this.state.copy(out, 0);

    this.state.fill(0);
    this.sigma.fill(0);
    this.block.fill(0);

    DESC.fill(0, 0, 8);

    this.size = FINALIZED;

    return out;
  }

  _transform(chunk, pos) {
    const m = chunk.slice(pos, pos + 32);

    this._f(m);
    this._sum(m);
  }

  _shuffle(m, s) {
    const res = Buffer.alloc(32);
    s.copy(res, 0);

    for (let i = 0; i < 12; i++)
      psi(res);

    XM(res, m);
    psi(res);
    XM(this.state, res);

    for (let i = 0; i < 61; i++)
      psi(this.state);
  }

  _f(m) {
    const s = Buffer.alloc(32);

    this.state.copy(s, 0);

    let k, u, v;

    k = P(X(this.state, m));
    encrypt(s, 0, k, this.S);

    u = A(this.state);
    v = A(A(m));
    k = P(X(u, v));
    encrypt(s, 8, k, this.S);

    u = A(u);
    XM(u, C);
    v = A(A(v));
    k = P(X(u, v));
    encrypt(s, 16, k, this.S);

    u = A(u);
    v = A(A(v));
    k = P(X(u, v));
    encrypt(s, 24, k, this.S);

    this._shuffle(m, s);
  }

  _sum(m) {
    let c = 0;

    for (let i = 0; i < 32; i++) {
      c += this.sigma[i] + m[i];
      this.sigma[i] = c;
      c >>>= 8;
    }
  }

  static hash() {
    return new GOST94();
  }

  static hmac(box) {
    return new HMAC(GOST94, 32, [box]);
  }

  static digest(data, box) {
    return GOST94.ctx.init(box).update(data).final();
  }

  static root(left, right, box) {
    assert(Buffer.isBuffer(left) && left.length === 32);
    assert(Buffer.isBuffer(right) && right.length === 32);
    return GOST94.ctx.init(box).update(left).update(right).final();
  }

  static multi(x, y, z, box) {
    const {ctx} = GOST94;

    ctx.init(box);
    ctx.update(x);
    ctx.update(y);

    if (z)
      ctx.update(z);

    return ctx.final();
  }

  static mac(data, key, box) {
    return GOST94.hmac(box).init(key).update(data).final();
  }
}

/*
 * Static
 */

GOST94.native = 0;
GOST94.id = 'GOST94';
GOST94.size = 32;
GOST94.bits = 256;
GOST94.blockSize = 32;
GOST94.zero = Buffer.alloc(32, 0x00);
GOST94.ctx = new GOST94();

GOST94.CRYPTOPRO = S_CRYPTOPRO;
GOST94.TEST = S_TEST;
GOST94.S2015 = S_S2015;

/*
 * Helpers
 */

function sbox(a, S) {
  let v = 0;

  for (let i = 0; i < 8; i++) {
    const shft = 4 * i;
    const k = (a & (15 << shft)) >>> shft;
    v += S[i][k] << shft;
  }

  return v >>> 0;
}

function G(a, k, S) {
  return rotl32(sbox((a + k) >>> 0, S), 11);
}

function encrypt(msg, pos, key, sbox) {
  const k = new Uint32Array(8);

  let a = readU32(msg, pos + 0);
  let b = readU32(msg, pos + 4);

  for (let i = 0; i < 8; i++)
    k[i] = readU32(key, i * 4);

  for (let x = 0; x < 3; x++) {
    for (let i = 0; i < 8; i++) {
      const t = b ^ G(a, k[i], sbox);
      b = a;
      a = t;
    }
  }

  for (let i = 7; i >= 0; i--) {
    const t = b ^ G(a, k[i], sbox);
    b = a;
    a = t;
  }

  writeU32(msg, b, pos + 0);
  writeU32(msg, a, pos + 4);
}

function X(a, b) {
  const out = Buffer.alloc(32);

  for (let i = 0; i < 32; i++)
    out[i] = a[i] ^ b[i];

  return out;
}

function XM(a, b) {
  for (let i = 0; i < 32; i++)
    a[i] ^= b[i];
}

function A(x) {
  const out = Buffer.alloc(32);

  x.copy(out, 0, 8, 32);

  for (let i = 0; i < 8; i++)
    out[24 + i] = x[i] ^ x[i + 8];

  return out;
}

function P(y) {
  const out = Buffer.alloc(32);

  for (let i = 0; i < 4; i++) {
    for (let k = 0; k < 8; k++)
      out[i + 4 * k] = y[8 * i + k];
  }

  return out;
}

function psi(block) {
  const out = Buffer.alloc(32);

  block.copy(out, 0, 2, 32);
  block.copy(out, 30, 0, 2);

  out[30] ^= block[2];
  out[31] ^= block[3];

  out[30] ^= block[4];
  out[31] ^= block[5];

  out[30] ^= block[6];
  out[31] ^= block[7];

  out[30] ^= block[24];
  out[31] ^= block[25];

  out[30] ^= block[30];
  out[31] ^= block[31];

  out.copy(block, 0);
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

module.exports = GOST94;
