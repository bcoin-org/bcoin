/*!
 * ghash.js - ghash for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on golang/go:
 *   Copyright (c) 2009, The Go Authors. All rights reserved.
 *   https://github.com/golang/go
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/Galois/Counter_Mode
 *   https://dx.doi.org/10.6028/NIST.SP.800-38D
 *   https://github.com/golang/go/blob/master/src/crypto/cipher/gcm.go
 *   https://github.com/golang/go/blob/master/src/crypto/cipher/gcm_test.go
 *   https://github.com/DaGenix/rust-crypto/blob/master/src/ghash.rs
 */

'use strict';

const assert = require('../../internal/assert');

/*
 * Constants
 */

const PADDING = Buffer.alloc(16, 0x00);
const FINALIZED = -1;

const REDUCTION = new Uint16Array([
  0x0000, 0x1c20, 0x3840, 0x2460,
  0x7080, 0x6ca0, 0x48c0, 0x54e0,
  0xe100, 0xfd20, 0xd940, 0xc560,
  0x9180, 0x8da0, 0xa9c0, 0xb5e0
]);

/**
 * GHASH
 */

class GHASH {
  constructor() {
    this.state = new Uint32Array(4);
    this.block = Buffer.alloc(16);
    this.size = FINALIZED;
    this.adLen = 0;
    this.ctLen = 0;
    this.table = new Array(16);

    for (let i = 0; i < 16; i++)
      this.table[i] = new Uint32Array(4);
  }

  init(key) {
    assert(Buffer.isBuffer(key));
    assert(key.length === 16);

    for (let i = 0; i < 4; i++)
      this.state[i] = 0;

    this.size = 0;
    this.adLen = 0;
    this.ctLen = 0;

    for (let i = 0; i < 16; i++) {
      for (let j = 0; j < 4; j++)
        this.table[i][j] = 0;
    }

    const x = new Uint32Array(4);

    x[1] = readU32(key, 0);
    x[0] = readU32(key, 4);
    x[3] = readU32(key, 8);
    x[2] = readU32(key, 12);

    this.table[reverse(1)] = x;

    for (let i = 2; i < 16; i += 2) {
      this.table[reverse(i)] = this.double(this.table[reverse(i >>> 1)]);
      this.table[reverse(i + 1)] = this.add(this.table[reverse(i)], x);
    }

    return this;
  }

  absorb(data) {
    this._absorb(data, data.length);
    return this;
  }

  _absorb(data, len) {
    assert(this.size !== FINALIZED, 'Context is not initialized.');

    let pos = this.size & 15;
    let off = 0;

    this.size += len;

    if (pos > 0) {
      let want = 16 - pos;

      if (want > len)
        want = len;

      data.copy(this.block, pos, off, off + want);

      pos += want;
      len -= want;
      off += want;

      if (pos < 16)
        return;

      this.transform(this.block, 0);
    }

    while (len >= 16) {
      this.transform(data, off);
      off += 16;
      len -= 16;
    }

    if (len > 0)
      data.copy(this.block, 0, off, off + len);
  }

  transform(block, off) {
    this.state[1] ^= readU32(block, off + 0);
    this.state[0] ^= readU32(block, off + 4);
    this.state[3] ^= readU32(block, off + 8);
    this.state[2] ^= readU32(block, off + 12);
    this.mul(this.state);
  }

  pad() {
    const pos = this.size & 15;

    if (pos !== 0)
      this._absorb(PADDING, 16 - pos);
  }

  aad(data) {
    assert(Buffer.isBuffer(data));
    assert(this.ctLen === 0);

    this.adLen += data.length;

    return this.absorb(data);
  }

  update(data) {
    assert(Buffer.isBuffer(data));

    if (data.length === 0)
      return this;

    if (this.ctLen === 0)
      this.pad();

    this.ctLen += data.length;

    return this.absorb(data);
  }

  final() {
    const out = Buffer.alloc(16);

    this.pad();

    const adLen = this.adLen * 8;
    const ctLen = this.ctLen * 8;

    this.state[1] ^= hi32(adLen);
    this.state[0] ^= lo32(adLen);
    this.state[3] ^= hi32(ctLen);
    this.state[2] ^= lo32(ctLen);

    this.mul(this.state);

    writeU32(out, this.state[1], 0);
    writeU32(out, this.state[0], 4);
    writeU32(out, this.state[3], 8);
    writeU32(out, this.state[2], 12);

    for (let i = 0; i < 4; i++)
      this.state[i] = 0;

    for (let i = 0; i < 16; i++)
      this.block[i] = 0;

    this.size = FINALIZED;
    this.adLen = 0;
    this.ctLen = 0;

    for (let i = 0; i < 16; i++) {
      for (let j = 0; j < 4; j++)
        this.table[i][j] = 0;
    }

    return out;
  }

  destroy() {
    for (let i = 0; i < 4; i++)
      this.state[i] = 0;

    for (let i = 0; i < 16; i++)
      this.block[i] = 0;

    this.size = FINALIZED;
    this.adLen = 0;
    this.ctLen = 0;

    for (let i = 0; i < 16; i++) {
      for (let j = 0; j < 4; j++)
        this.table[i][j] = 0;
    }
  }

  add(x, y) {
    assert(x instanceof Uint32Array);
    assert(x.length === 4);
    assert(y instanceof Uint32Array);
    assert(y.length === 4);

    const z = new Uint32Array(4);

    z[0] = x[0] ^ y[0];
    z[1] = x[1] ^ y[1];
    z[2] = x[2] ^ y[2];
    z[3] = x[3] ^ y[3];

    return z;
  }

  double(x) {
    assert(x instanceof Uint32Array);
    assert(x.length === 4);

    const d = new Uint32Array(4);
    const msb = (x[2] & 1) === 1;

    let v;

    d[3] = x[3];
    d[2] = x[2];
    v = d[3] & 1;
    d[3] >>>= 1;
    d[2] >>>= 1;
    d[2] |= v << 31;

    d[3] |= (x[0] & 1) << 31;

    d[1] = x[1];
    d[0] = x[0];
    v = d[1] & 1;
    d[1] >>>= 1;
    d[0] >>>= 1;
    d[0] |= v << 31;

    if (msb) {
      d[1] ^= 0xe1000000;
      d[0] ^= 0x00000000;
    }

    return d;
  }

  mul(y) {
    assert(y instanceof Uint32Array);
    assert(y.length === 4);

    const z = new Uint32Array(4);
    const w = new Uint32Array(2);

    let v, t;

    for (let i = 0; i < 2; i++) {
      w[0] = y[2];
      w[1] = y[3];

      if (i === 1) {
        w[0] = y[0];
        w[1] = y[1];
      }

      for (let j = 0; j < 64; j += 4) {
        const msw = z[2] & 0x0f;

        v = z[3] & 0x0f;
        z[3] >>>= 4;
        z[2] >>>= 4;
        z[2] |= v << 28;

        z[3] |= z[0] << 28;

        v = z[1] & 0x0f;
        z[1] >>>= 4;
        z[0] >>>= 4;
        z[0] |= v << 28;

        z[1] ^= REDUCTION[msw] << 16;

        t = this.table[w[0] & 0x0f];

        z[0] ^= t[0];
        z[1] ^= t[1];

        z[2] ^= t[2];
        z[3] ^= t[3];

        v = w[1] & 0x0f;
        w[1] >>>= 4;
        w[0] >>>= 4;
        w[0] |= v << 28;
      }
    }

    y[0] = z[0];
    y[1] = z[1];
    y[2] = z[2];
    y[3] = z[3];
  }
}

/*
 * Helpers
 */

function hi32(num) {
  return (num * (1 / 0x100000000)) >>> 0;
}

function lo32(num) {
  return num >>> 0;
}

function reverse(i) {
  i = ((i << 2) & 0x0c) | ((i >>> 2) & 0x03);
  i = ((i << 1) & 0x0a) | ((i >>> 1) & 0x05);
  return i;
}

function readU32(data, off) {
  return (data[off++] * 0x1000000
        + data[off++] * 0x10000
        + data[off++] * 0x100
        + data[off++]);
}

function writeU32(dst, num, off) {
  dst[off++] = num >>> 24;
  dst[off++] = num >>> 16;
  dst[off++] = num >>> 8;
  dst[off++] = num;
  return off;
}

/*
 * Expose
 */

module.exports = GHASH;
