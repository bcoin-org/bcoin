/*!
 * gcm.js - gcm for javascript
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

/**
 * CTR
 */

class CTR {
  constructor(ctx) {
    assert(ctx && typeof ctx === 'object');
    assert(typeof ctx.blockSize === 'number');

    if (ctx.blockSize !== 16)
      throw new Error('GCM only available with a 128 bit block size.');

    this.ctx = ctx;
    this.state = Buffer.alloc(16);
    this.block = Buffer.alloc(16);
    this.pos = 0;
  }

  init(key) {
    this.ctx.init(key);

    for (let i = 0; i < 16; i++)
      this.state[i] = 0;

    this.pos = 0;

    return this;
  }

  set(nonce) {
    assert(Buffer.isBuffer(nonce));
    assert(nonce.length === 12 || nonce.length === 16);

    this.state[0] = nonce[0];
    this.state[1] = nonce[1];
    this.state[2] = nonce[2];
    this.state[3] = nonce[3];
    this.state[4] = nonce[4];
    this.state[5] = nonce[5];
    this.state[6] = nonce[6];
    this.state[7] = nonce[7];
    this.state[8] = nonce[8];
    this.state[9] = nonce[9];
    this.state[10] = nonce[10];
    this.state[11] = nonce[11];

    if (nonce.length === 16) {
      this.state[12] = nonce[12];
      this.state[13] = nonce[13];
      this.state[14] = nonce[14];
      this.state[15] = nonce[15];
    } else {
      this.state[12] = 0x00;
      this.state[13] = 0x00;
      this.state[14] = 0x00;
      this.state[15] = 0x01;
    }

    return this;
  }

  encrypt(data) {
    assert(Buffer.isBuffer(data));

    for (let i = 0; i < data.length; i++) {
      if ((this.pos & 15) === 0) {
        this.ctx.encrypt(this.state, 0, this.block, 0);

        for (let j = 15; j >= 12; j--) {
          this.state[j] += 1;

          if (this.state[j] !== 0)
            break;
        }

        this.pos = 0;
      }

      data[i] ^= this.block[this.pos++];
    }

    return data;
  }

  destroy() {
    this.ctx.destroy();

    for (let i = 0; i < 16; i++) {
      this.state[i] = 0;
      this.block[i] = 0;
    }

    this.pos = 0;

    return this;
  }
}

/**
 * GCM
 */

class GCM {
  constructor(ctx) {
    this.cipher = new CTR(ctx);
    this.mac = new GHASH();
    this.key = Buffer.alloc(16);
    this.mask = Buffer.alloc(16);
    this.mode = -1;
  }

  init(key, iv) {
    assert(Buffer.isBuffer(iv));

    for (let i = 0; i < 16; i++) {
      this.key[i] = 0;
      this.mask[i] = 0;
    }

    this.mode = 0;

    this.cipher.init(key);
    this.cipher.encrypt(this.key);
    this.mac.init(this.key);

    // Full round of ghash with same key.
    if (iv.length !== 12) {
      this.mac.update(iv);
      iv = this.mac.final();
      this.mac.init(this.key);
    }

    this.cipher.set(iv);
    this.cipher.encrypt(this.mask);

    return this;
  }

  aad(data) {
    if (this.mode === -1)
      throw new Error('Cipher is not initialized.');

    if (this.mode !== 0)
      throw new Error('Invalid state for aad.');

    this.mac.aad(data);

    return this;
  }

  encrypt(data) {
    if (this.mode === -1)
      throw new Error('Cipher is not initialized.');

    if (this.mode !== 0 && this.mode !== 1)
      throw new Error('Invalid state for encrypt.');

    this.mode = 1;
    this.cipher.encrypt(data);
    this.mac.update(data);

    return data;
  }

  decrypt(data) {
    if (this.mode === -1)
      throw new Error('Cipher is not initialized.');

    if (this.mode !== 0 && this.mode !== 2)
      throw new Error('Invalid state for decrypt.');

    this.mode = 2;
    this.mac.update(data);
    this.cipher.encrypt(data);

    return data;
  }

  auth(data) {
    if (this.mode === -1)
      throw new Error('Cipher is not initialized.');

    if (this.mode !== 0 && this.mode !== 3)
      throw new Error('Invalid state for auth.');

    this.mode = 3;
    this.mac.update(data);

    return data;
  }

  final(size = 16) {
    assert((size >>> 0) === size);
    assert(size === 4 || size === 8
       || (size >= 12 && size <= 16));

    if (this.mode === -1)
      throw new Error('Cipher is not initialized.');

    const mac = this.mac.final();

    for (let i = 0; i < 16; i++)
      mac[i] ^= this.mask[i];

    this.mode = -1;

    return mac.slice(0, size);
  }

  verify(tag) {
    assert(Buffer.isBuffer(tag));

    const mac = this.final(tag.length);

    let z = 0;

    for (let i = 0; i < mac.length; i++)
      z |= mac[i] ^ tag[i];

    return ((z - 1) >>> 31) !== 0;
  }

  destroy() {
    this.cipher.destroy();
    this.mac.destroy();

    for (let i = 0; i < 16; i++) {
      this.key[i] = 0;
      this.mask[i] = 0;
    }

    this.mode = -1;
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

exports.GHASH = GHASH;
exports.CTR = CTR;
exports.GCM = GCM;
