/*!
 * blake2s.js - BLAKE2s implementation for bcrypto
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on blakejs:
 *   https://github.com/dcposch/blakejs/blob/master/blake2s.js
 */

'use strict';

const assert = require('bsert');
const HMAC = require('../internal/hmac');

/*
 * Constants
 */

const FINALIZED = 0x80000000;

const IV = new Uint32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]);

const SIGMA = new Uint8Array([
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x0e, 0x0a, 0x04, 0x08, 0x09, 0x0f, 0x0d, 0x06,
  0x01, 0x0c, 0x00, 0x02, 0x0b, 0x07, 0x05, 0x03,
  0x0b, 0x08, 0x0c, 0x00, 0x05, 0x02, 0x0f, 0x0d,
  0x0a, 0x0e, 0x03, 0x06, 0x07, 0x01, 0x09, 0x04,
  0x07, 0x09, 0x03, 0x01, 0x0d, 0x0c, 0x0b, 0x0e,
  0x02, 0x06, 0x05, 0x0a, 0x04, 0x00, 0x0f, 0x08,
  0x09, 0x00, 0x05, 0x07, 0x02, 0x04, 0x0a, 0x0f,
  0x0e, 0x01, 0x0b, 0x0c, 0x06, 0x08, 0x03, 0x0d,
  0x02, 0x0c, 0x06, 0x0a, 0x00, 0x0b, 0x08, 0x03,
  0x04, 0x0d, 0x07, 0x05, 0x0f, 0x0e, 0x01, 0x09,
  0x0c, 0x05, 0x01, 0x0f, 0x0e, 0x0d, 0x04, 0x0a,
  0x00, 0x07, 0x06, 0x03, 0x09, 0x02, 0x08, 0x0b,
  0x0d, 0x0b, 0x07, 0x0e, 0x0c, 0x01, 0x03, 0x09,
  0x05, 0x00, 0x0f, 0x04, 0x08, 0x06, 0x02, 0x0a,
  0x06, 0x0f, 0x0e, 0x09, 0x0b, 0x03, 0x00, 0x08,
  0x0c, 0x02, 0x0d, 0x07, 0x01, 0x04, 0x0a, 0x05,
  0x0a, 0x02, 0x08, 0x04, 0x07, 0x06, 0x01, 0x05,
  0x0f, 0x0b, 0x09, 0x0e, 0x03, 0x0c, 0x0d, 0x00
]);

const V = new Uint32Array(16);
const M = new Uint32Array(16);
const BLOCK = Buffer.alloc(64, 0x00);

/**
 * BLAKE2s
 */

class BLAKE2s {
  /**
   * Create a BLAKE2s context.
   * @constructor
   */

  constructor() {
    this.state = new Uint32Array(8);
    this.block = Buffer.allocUnsafe(64);
    this.size = 32;
    this.count = 0;
    this.pos = FINALIZED;
  }

  init(size = 32, key = null) {
    assert((size >>> 0) === size);
    assert(!key || Buffer.isBuffer(key));

    if (size === 0 || size > 32)
      throw new Error('Bad output length.');

    if (key && key.length > 32)
      throw new Error('Bad key length.');

    const klen = key ? key.length : 0;

    for (let i = 0; i < 8; i++)
      this.state[i] = IV[i];

    this.size = size;
    this.count = 0;
    this.pos = 0;

    this.state[0] ^= 0x01010000 ^ (klen << 8) ^ this.size;

    if (klen > 0) {
      const block = BLOCK;

      key.copy(block, 0);

      this.update(block);

      block.fill(0x00, 0, key.length);
    }

    return this;
  }

  update(data) {
    assert(Buffer.isBuffer(data));
    assert(!(this.pos & FINALIZED), 'Context already finalized.');

    let off = 0;
    let len = data.length;

    if (len > 0) {
      const left = this.pos;
      const fill = 64 - left;

      if (len > fill) {
        this.pos = 0;

        data.copy(this.block, left, off, off + fill);

        this.count += 64;
        this.compress(this.block, 0, false);

        off += fill;
        len -= fill;

        while (len > 64) {
          this.count += 64;
          this.compress(data, off, false);
          off += 64;
          len -= 64;
        }
      }

      data.copy(this.block, this.pos, off, off + len);

      this.pos += len;
    }

    return this;
  }

  final() {
    assert(!(this.pos & FINALIZED), 'Context already finalized.');

    this.count += this.pos;
    this.block.fill(0, this.pos, 64);
    this.compress(this.block, 0, true);
    this.pos = FINALIZED;

    const out = Buffer.allocUnsafe(this.size);

    for (let i = 0; i < this.size; i++)
      out[i] = this.state[i >>> 2] >>> (8 * (i & 3));

    for (let i = 0; i < 8; i++)
      this.state[i] = 0;

    for (let i = 0; i < 64; i++)
      this.block[i] = 0;

    return out;
  }

  compress(block, off, last) {
    for (let i = 0; i < 8; i++) {
      V[i] = this.state[i];
      V[i + 8] = IV[i];
    }

    // uint64
    V[12] ^= this.count;
    V[13] ^= this.count * (1 / 0x100000000);

    if (last) {
      // last block
      V[14] ^= -1;

      // last node
      V[15] ^= 0;
    }

    for (let i = 0; i < 16; i++) {
      M[i] = readU32(block, off);
      off += 4;
    }

    for (let i = 0; i < 10; i++) {
      G(V, M, 0, 4, 8, 12, SIGMA[i * 16 + 0], SIGMA[i * 16 + 1]);
      G(V, M, 1, 5, 9, 13, SIGMA[i * 16 + 2], SIGMA[i * 16 + 3]);
      G(V, M, 2, 6, 10, 14, SIGMA[i * 16 + 4], SIGMA[i * 16 + 5]);
      G(V, M, 3, 7, 11, 15, SIGMA[i * 16 + 6], SIGMA[i * 16 + 7]);
      G(V, M, 0, 5, 10, 15, SIGMA[i * 16 + 8], SIGMA[i * 16 + 9]);
      G(V, M, 1, 6, 11, 12, SIGMA[i * 16 + 10], SIGMA[i * 16 + 11]);
      G(V, M, 2, 7, 8, 13, SIGMA[i * 16 + 12], SIGMA[i * 16 + 13]);
      G(V, M, 3, 4, 9, 14, SIGMA[i * 16 + 14], SIGMA[i * 16 + 15]);
    }

    for (let i = 0; i < 8; i++)
      this.state[i] ^= V[i] ^ V[i + 8];
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

BLAKE2s.native = 0;
BLAKE2s.id = 'BLAKE2S256';
BLAKE2s.size = 32;
BLAKE2s.bits = 256;
BLAKE2s.blockSize = 64;
BLAKE2s.zero = Buffer.alloc(32, 0x00);
BLAKE2s.ctx = new BLAKE2s();

/*
 * Helpers
 */

function rotr32(x, y) {
  return (x >>> y) ^ (x << (32 - y));
}

function readU32(data, off) {
  return data[off]
    ^ (data[off + 1] << 8)
    ^ (data[off + 2] << 16)
    ^ (data[off + 3] << 24);
}

function G(v, m, a, b, c, d, ix, iy) {
  const x = m[ix];
  const y = m[iy];

  v[a] = v[a] + v[b] + x;
  v[d] = rotr32(v[d] ^ v[a], 16);
  v[c] = v[c] + v[d];
  v[b] = rotr32(v[b] ^ v[c], 12);
  v[a] = v[a] + v[b] + y;
  v[d] = rotr32(v[d] ^ v[a], 8);
  v[c] = v[c] + v[d];
  v[b] = rotr32(v[b] ^ v[c], 7);
}

/*
 * Expose
 */

module.exports = BLAKE2s;
