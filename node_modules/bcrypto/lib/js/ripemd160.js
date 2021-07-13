/*!
 * ripemd160.js - RIPEMD160 implementation for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on indutny/hash.js:
 *   Copyright (c) 2014, Fedor Indutny (MIT License).
 *   https://github.com/indutny/hash.js
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/RIPEMD-160
 *   https://homes.esat.kuleuven.be/~bosselae/ripemd160/pdf/AB-9601/AB-9601.pdf
 *   https://github.com/indutny/hash.js/blob/master/lib/hash/ripemd.js
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

const r = new Uint8Array([
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
  7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
  3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
  1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
  4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13
]);

const rh = new Uint8Array([
  5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
  6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
  15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
  8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
  12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
]);

const s = new Uint8Array([
  11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
  7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
  11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
  11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
  9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
]);

const sh = new Uint8Array([
  8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
  9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
  9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
  15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
  8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
]);

/**
 * RIPEMD160
 */

class RIPEMD160 {
  constructor() {
    this.state = new Uint32Array(5);
    this.msg = new Uint32Array(16);
    this.block = Buffer.alloc(64);
    this.size = FINALIZED;
  }

  init() {
    this.state[0] = 0x67452301;
    this.state[1] = 0xefcdab89;
    this.state[2] = 0x98badcfe;
    this.state[3] = 0x10325476;
    this.state[4] = 0xc3d2e1f0;
    this.size = 0;
    return this;
  }

  update(data) {
    assert(Buffer.isBuffer(data));
    this._update(data, data.length);
    return this;
  }

  final() {
    return this._final(Buffer.alloc(20));
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

  _final(out) {
    assert(this.size !== FINALIZED, 'Context is not initialized.');

    const pos = this.size & 63;
    const len = this.size * 8;

    writeU32(DESC, len >>> 0, 0);
    writeU32(DESC, (len * (1 / 0x100000000)) >>> 0, 4);

    this._update(PADDING, 1 + ((119 - pos) & 63));
    this._update(DESC, 8);

    for (let i = 0; i < 5; i++) {
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

    let A = this.state[0];
    let B = this.state[1];
    let C = this.state[2];
    let D = this.state[3];
    let E = this.state[4];
    let Ah = A;
    let Bh = B;
    let Ch = C;
    let Dh = D;
    let Eh = E;

    for (let i = 0; i < 16; i++)
      W[i] = readU32(chunk, pos + i * 4);

    for (let j = 0; j < 80; j++) {
      let a = A + f(j, B, C, D) + W[r[j]] + K(j);
      let b = rotl32(a, s[j]);
      let T = b + E;

      A = E;
      E = D;
      D = rotl32(C, 10);
      C = B;
      B = T;

      a = Ah + f(79 - j, Bh, Ch, Dh) + W[rh[j]] + Kh(j);
      b = rotl32(a, sh[j]);
      T = b + Eh;
      Ah = Eh;
      Eh = Dh;
      Dh = rotl32(Ch, 10);
      Ch = Bh;
      Bh = T;
    }

    const T = this.state[1] + C + Dh;

    this.state[1] = this.state[2] + D + Eh;
    this.state[2] = this.state[3] + E + Ah;
    this.state[3] = this.state[4] + A + Bh;
    this.state[4] = this.state[0] + B + Ch;
    this.state[0] = T;
  }

  static hash() {
    return new RIPEMD160();
  }

  static hmac() {
    return new HMAC(RIPEMD160, 64);
  }

  static digest(data) {
    return RIPEMD160.ctx.init().update(data).final();
  }

  static root(left, right) {
    assert(Buffer.isBuffer(left) && left.length === 20);
    assert(Buffer.isBuffer(right) && right.length === 20);
    return RIPEMD160.ctx.init().update(left).update(right).final();
  }

  static multi(x, y, z) {
    const {ctx} = RIPEMD160;

    ctx.init();
    ctx.update(x);
    ctx.update(y);

    if (z)
      ctx.update(z);

    return ctx.final();
  }

  static mac(data, key) {
    return RIPEMD160.hmac().init(key).update(data).final();
  }
}

/*
 * Static
 */

RIPEMD160.native = 0;
RIPEMD160.id = 'RIPEMD160';
RIPEMD160.size = 20;
RIPEMD160.bits = 160;
RIPEMD160.blockSize = 64;
RIPEMD160.zero = Buffer.alloc(20, 0x00);
RIPEMD160.ctx = new RIPEMD160();

/*
 * Helpers
 */

function rotl32(w, b) {
  return (w << b) | (w >>> (32 - b));
}

function f(j, x, y, z) {
  if (j <= 15)
    return x ^ y ^ z;

  if (j <= 31)
    return (x & y) | ((~x) & z);

  if (j <= 47)
    return (x | (~y)) ^ z;

  if (j <= 63)
    return (x & z) | (y & (~z));

  return x ^ (y | (~z));
}

function K(j) {
  if (j <= 15)
    return 0x00000000;

  if (j <= 31)
    return 0x5a827999;

  if (j <= 47)
    return 0x6ed9eba1;

  if (j <= 63)
    return 0x8f1bbcdc;

  return 0xa953fd4e;
}

function Kh(j) {
  if (j <= 15)
    return 0x50a28be6;

  if (j <= 31)
    return 0x5c4dd124;

  if (j <= 47)
    return 0x6d703ef3;

  if (j <= 63)
    return 0x7a6d76e9;

  return 0x00000000;
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

module.exports = RIPEMD160;
