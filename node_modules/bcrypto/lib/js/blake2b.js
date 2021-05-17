/*!
 * blake2b.js - BLAKE2b implementation for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on dcposch/blakejs:
 *   Daniel Clemens Posch (CC0)
 *   https://github.com/dcposch/blakejs/blob/master/blake2b.js
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/BLAKE_(hash_function)
 *   https://tools.ietf.org/html/rfc7693
 */

'use strict';

const assert = require('../internal/assert');
const HMAC = require('../internal/hmac');

/*
 * Constants
 */

const FINALIZED = 0x80000000;

const IV = new Uint32Array([
  0xf3bcc908, 0x6a09e667, 0x84caa73b, 0xbb67ae85,
  0xfe94f82b, 0x3c6ef372, 0x5f1d36f1, 0xa54ff53a,
  0xade682d1, 0x510e527f, 0x2b3e6c1f, 0x9b05688c,
  0xfb41bd6b, 0x1f83d9ab, 0x137e2179, 0x5be0cd19
]);

const SIGMA = new Uint8Array([
  0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e,
  0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e,
  0x1c, 0x14, 0x08, 0x10, 0x12, 0x1e, 0x1a, 0x0c,
  0x02, 0x18, 0x00, 0x04, 0x16, 0x0e, 0x0a, 0x06,
  0x16, 0x10, 0x18, 0x00, 0x0a, 0x04, 0x1e, 0x1a,
  0x14, 0x1c, 0x06, 0x0c, 0x0e, 0x02, 0x12, 0x08,
  0x0e, 0x12, 0x06, 0x02, 0x1a, 0x18, 0x16, 0x1c,
  0x04, 0x0c, 0x0a, 0x14, 0x08, 0x00, 0x1e, 0x10,
  0x12, 0x00, 0x0a, 0x0e, 0x04, 0x08, 0x14, 0x1e,
  0x1c, 0x02, 0x16, 0x18, 0x0c, 0x10, 0x06, 0x1a,
  0x04, 0x18, 0x0c, 0x14, 0x00, 0x16, 0x10, 0x06,
  0x08, 0x1a, 0x0e, 0x0a, 0x1e, 0x1c, 0x02, 0x12,
  0x18, 0x0a, 0x02, 0x1e, 0x1c, 0x1a, 0x08, 0x14,
  0x00, 0x0e, 0x0c, 0x06, 0x12, 0x04, 0x10, 0x16,
  0x1a, 0x16, 0x0e, 0x1c, 0x18, 0x02, 0x06, 0x12,
  0x0a, 0x00, 0x1e, 0x08, 0x10, 0x0c, 0x04, 0x14,
  0x0c, 0x1e, 0x1c, 0x12, 0x16, 0x06, 0x00, 0x10,
  0x18, 0x04, 0x1a, 0x0e, 0x02, 0x08, 0x14, 0x0a,
  0x14, 0x04, 0x10, 0x08, 0x0e, 0x0c, 0x02, 0x0a,
  0x1e, 0x16, 0x12, 0x1c, 0x06, 0x18, 0x1a, 0x00,
  0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e,
  0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e,
  0x1c, 0x14, 0x08, 0x10, 0x12, 0x1e, 0x1a, 0x0c,
  0x02, 0x18, 0x00, 0x04, 0x16, 0x0e, 0x0a, 0x06
]);

/**
 * BLAKE2b
 */

class BLAKE2b {
  constructor() {
    this.state = new Uint32Array(16);
    this.V = new Uint32Array(32);
    this.M = new Uint32Array(32);
    this.block = Buffer.alloc(128);
    this.size = 32;
    this.count = 0;
    this.pos = FINALIZED;
  }

  init(size, key) {
    if (size == null)
      size = 32;

    assert((size >>> 0) === size);
    assert(key == null || Buffer.isBuffer(key));

    if (size === 0 || size > 64)
      throw new Error('Bad output length.');

    if (key && key.length > 64)
      throw new Error('Bad key length.');

    const klen = key ? key.length : 0;

    for (let i = 0; i < 16; i++)
      this.state[i] = IV[i];

    this.size = size;
    this.count = 0;
    this.pos = 0;

    this.state[0] ^= 0x01010000 ^ (klen << 8) ^ this.size;

    if (klen > 0) {
      const block = Buffer.alloc(128, 0x00);

      key.copy(block, 0);

      this.update(block);
    }

    return this;
  }

  update(data) {
    assert(Buffer.isBuffer(data));
    assert(!(this.pos & FINALIZED), 'Context is not initialized.');

    let off = 0;
    let len = data.length;

    if (len > 0) {
      const left = this.pos;
      const fill = 128 - left;

      if (len > fill) {
        this.pos = 0;

        data.copy(this.block, left, off, off + fill);

        this.count += 128;
        this._compress(this.block, 0, false);

        off += fill;
        len -= fill;

        while (len > 128) {
          this.count += 128;
          this._compress(data, off, false);
          off += 128;
          len -= 128;
        }
      }

      data.copy(this.block, this.pos, off, off + len);

      this.pos += len;
    }

    return this;
  }

  final() {
    assert(!(this.pos & FINALIZED), 'Context is not initialized.');

    this.count += this.pos;
    this.block.fill(0, this.pos, 128);
    this._compress(this.block, 0, true);
    this.pos = FINALIZED;

    const out = Buffer.alloc(this.size);

    for (let i = 0; i < this.size; i++)
      out[i] = this.state[i >>> 2] >>> (8 * (i & 3));

    for (let i = 0; i < 16; i++)
      this.state[i] = 0;

    for (let i = 0; i < 32; i++) {
      this.V[i] = 0;
      this.M[i] = 0;
    }

    for (let i = 0; i < 128; i++)
      this.block[i] = 0;

    return out;
  }

  _compress(block, off, last) {
    const {V, M} = this;

    for (let i = 0; i < 16; i++) {
      V[i] = this.state[i];
      V[i + 16] = IV[i];
    }

    // uint128
    V[24] ^= this.count;
    V[25] ^= this.count * (1 / 0x100000000);
    V[26] ^= 0;
    V[27] ^= 0;

    if (last) {
      // last block
      V[28] ^= -1;
      V[29] ^= -1;

      // last node
      V[29] ^= 0;
      V[30] ^= 0;
    }

    for (let i = 0; i < 32; i++) {
      M[i] = readU32(block, off);
      off += 4;
    }

    for (let i = 0; i < 12; i++) {
      G(V, M, 0, 8, 16, 24, SIGMA[i * 16 + 0], SIGMA[i * 16 + 1]);
      G(V, M, 2, 10, 18, 26, SIGMA[i * 16 + 2], SIGMA[i * 16 + 3]);
      G(V, M, 4, 12, 20, 28, SIGMA[i * 16 + 4], SIGMA[i * 16 + 5]);
      G(V, M, 6, 14, 22, 30, SIGMA[i * 16 + 6], SIGMA[i * 16 + 7]);
      G(V, M, 0, 10, 20, 30, SIGMA[i * 16 + 8], SIGMA[i * 16 + 9]);
      G(V, M, 2, 12, 22, 24, SIGMA[i * 16 + 10], SIGMA[i * 16 + 11]);
      G(V, M, 4, 14, 16, 26, SIGMA[i * 16 + 12], SIGMA[i * 16 + 13]);
      G(V, M, 6, 8, 18, 28, SIGMA[i * 16 + 14], SIGMA[i * 16 + 15]);
    }

    for (let i = 0; i < 16; i++)
      this.state[i] ^= V[i] ^ V[i + 16];
  }

  static hash() {
    return new BLAKE2b();
  }

  static hmac(size) {
    return new HMAC(BLAKE2b, 128, [size]);
  }

  static digest(data, size, key) {
    const {ctx} = BLAKE2b;

    ctx.init(size, key);
    ctx.update(data);

    return ctx.final();
  }

  static root(left, right, size, key) {
    if (size == null)
      size = 32;

    assert(Buffer.isBuffer(left) && left.length === size);
    assert(Buffer.isBuffer(right) && right.length === size);

    const {ctx} = BLAKE2b;

    ctx.init(size, key);
    ctx.update(left);
    ctx.update(right);

    return ctx.final();
  }

  static multi(x, y, z, size, key) {
    const {ctx} = BLAKE2b;

    ctx.init(size, key);
    ctx.update(x);
    ctx.update(y);

    if (z)
      ctx.update(z);

    return ctx.final();
  }

  static mac(data, key, size) {
    return BLAKE2b.hmac(size).init(key).update(data).final();
  }
}

/*
 * Static
 */

BLAKE2b.native = 0;
BLAKE2b.id = 'BLAKE2B256';
BLAKE2b.size = 32;
BLAKE2b.bits = 256;
BLAKE2b.blockSize = 128;
BLAKE2b.zero = Buffer.alloc(32, 0x00);
BLAKE2b.ctx = new BLAKE2b();

/*
 * Helpers
 */

function sum64i(v, a, b) {
  const o0 = v[a + 0] + v[b + 0];
  const o1 = v[a + 1] + v[b + 1];
  const c = (o0 >= 0x100000000) | 0;

  v[a + 0] = o0;
  v[a + 1] = o1 + c;
}

function sum64w(v, a, b0, b1) {
  const o0 = v[a + 0] + b0;
  const o1 = v[a + 1] + b1;
  const c = (o0 >= 0x100000000) | 0;

  v[a + 0] = o0;
  v[a + 1] = o1 + c;
}

function G(v, m, a, b, c, d, ix, iy) {
  const x0 = m[ix + 0];
  const x1 = m[ix + 1];
  const y0 = m[iy + 0];
  const y1 = m[iy + 1];

  sum64i(v, a, b);
  sum64w(v, a, x0, x1);

  const xor0 = v[d + 0] ^ v[a + 0];
  const xor1 = v[d + 1] ^ v[a + 1];

  v[d + 0] = xor1;
  v[d + 1] = xor0;

  sum64i(v, c, d);

  const xor2 = v[b + 0] ^ v[c + 0];
  const xor3 = v[b + 1] ^ v[c + 1];

  v[b + 0] = (xor2 >>> 24) ^ (xor3 << 8);
  v[b + 1] = (xor3 >>> 24) ^ (xor2 << 8);

  sum64i(v, a, b);
  sum64w(v, a, y0, y1);

  const xor4 = v[d + 0] ^ v[a + 0];
  const xor5 = v[d + 1] ^ v[a + 1];

  v[d + 0] = (xor4 >>> 16) ^ (xor5 << 16);
  v[d + 1] = (xor5 >>> 16) ^ (xor4 << 16);

  sum64i(v, c, d);

  const xor6 = v[b + 0] ^ v[c + 0];
  const xor7 = v[b + 1] ^ v[c + 1];

  v[b + 0] = (xor7 >>> 31) ^ (xor6 << 1);
  v[b + 1] = (xor6 >>> 31) ^ (xor7 << 1);
}

function readU32(data, off) {
  return (data[off++]
        + data[off++] * 0x100
        + data[off++] * 0x10000
        + data[off] * 0x1000000);
}

/*
 * Expose
 */

module.exports = BLAKE2b;
