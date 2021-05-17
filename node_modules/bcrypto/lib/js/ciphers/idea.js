/*!
 * idea.js - IDEA for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on dgryski/go-idea:
 *   Copyright (c) 2013-2017, Damian Gryski. All rights reserved.
 *   https://github.com/dgryski/go-idea
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/International_Data_Encryption_Algorithm
 *   https://github.com/dgryski/go-idea/blob/master/idea.go
 */

'use strict';

const assert = require('../../internal/assert');

/*
 * Constants
 */

const ZERO16 = Buffer.alloc(16, 0x00);

/**
 * IDEA
 */

class IDEA {
  constructor() {
    this.key = ZERO16;
    this.encryptKey = null;
    this.decryptKey = null;
  }

  get blockSize() {
    return 8;
  }

  init(key) {
    assert(Buffer.isBuffer(key));
    assert(key.length === 16);

    this.destroy();
    this.key = Buffer.from(key);

    return this;
  }

  getEncryptKey() {
    if (!this.encryptKey)
      this.encryptKey = this.expandKey(this.key);

    return this.encryptKey;
  }

  getDecryptKey() {
    if (!this.decryptKey)
      this.decryptKey = this.invertKey(this.getEncryptKey());

    return this.decryptKey;
  }

  encrypt(output, opos, input, ipos) {
    const key = this.getEncryptKey();
    return this.crypt(output, opos, input, ipos, key);
  }

  decrypt(output, opos, input, ipos) {
    const key = this.getDecryptKey();
    return this.crypt(output, opos, input, ipos, key);
  }

  destroy() {
    for (let i = 0; i < 16; i++)
      this.key[i] = 0;

    if (this.encryptKey) {
      for (let i = 0; i < 52; i++)
        this.encryptKey[i] = 0;
    }

    if (this.decryptKey) {
      for (let i = 0; i < 52; i++)
        this.decryptKey[i] = 0;
    }

    this.key = ZERO16;
    this.encryptKey = null;
    this.decryptKey = null;

    return this;
  }

  expandKey(key) {
    const K = new Uint16Array(52);

    let p = 0;
    let j = 0;
    let i = 0;

    for (; j < 8; j++)
      K[j] = readU16(key, j * 2);

    for (; j < 52; j++) {
      i += 1;

      K[p + (i + 7)] = (K[p + ((i + 0) & 7)] << 9)
                     | (K[p + ((i + 1) & 7)] >>> 7);

      p += i & 8;
      i &= 7;
    }

    return K;
  }

  invertKey(K) {
    const D = new Uint16Array(52);

    let t1, t2, t3;
    let di = 52 - 1;
    let ki = 0;

    t1 = invm(K[ki++]);
    t2 = -K[ki++];
    t3 = -K[ki++];

    D[di--] = invm(K[ki++]);
    D[di--] = t3;
    D[di--] = t2;
    D[di--] = t1;

    for (let i = 0; i < 8 - 1; i++) {
      t1 = K[ki++];

      D[di--] = K[ki++];
      D[di--] = t1;

      t1 = invm(K[ki++]);
      t2 = -K[ki++];
      t3 = -K[ki++];

      D[di--] = invm(K[ki++]);
      D[di--] = t2;
      D[di--] = t3;
      D[di--] = t1;
    }

    t1 = K[ki++];

    D[di--] = K[ki++];
    D[di--] = t1;

    t1 = invm(K[ki++]);
    t2 = -K[ki++];
    t3 = -K[ki++];

    D[di--] = invm(K[ki++]);
    D[di--] = t3;
    D[di--] = t2;
    D[di--] = t1;

    return D;
  }

  crypt(output, opos, input, ipos, key) {
    let x1 = readU16(input, ipos + 0);
    let x2 = readU16(input, ipos + 2);
    let x3 = readU16(input, ipos + 4);
    let x4 = readU16(input, ipos + 6);
    let s2 = 0;
    let s3 = 0;
    let p = 0;

    for (let i = 8 - 1; i >= 0; i--) {
      x1 = mul(x1, key[p++]);
      x2 += key[p++];
      x3 += key[p++];
      x4 = mul(x4, key[p++]);

      s3 = x3;
      x3 ^= x1;
      x3 = mul(x3, key[p++]);
      s2 = x2;

      x2 ^= x4;
      x2 += x3;
      x2 = mul(x2, key[p++]);
      x3 += x2;

      x1 ^= x2;
      x4 ^= x3;
      x2 ^= s3;
      x3 ^= s2;
    }

    x1 = mul(x1, key[p++]);
    x3 += key[p++];
    x2 += key[p++];
    x4 = mul(x4, key[p++]);

    writeU16(output, x1, opos + 0);
    writeU16(output, x3, opos + 2);
    writeU16(output, x2, opos + 4);
    writeU16(output, x4, opos + 6);
  }
}

/*
 * Helpers
 */

function invm(x) {
  x &= 0xffff;

  if (x <= 1)
    return x;

  let t1 = (0x10001 / x) & 0xffff;
  let y = 0x10001 % x;

  if (y === 1)
    return (1 - t1) & 0xffff;

  let t0 = 1;
  let q = 0;

  while (y !== 1) {
    q = (x / y) & 0xffff;
    x %= y;

    t0 += q * t1;
    t0 &= 0xffff;

    if (x === 1)
      return t0;

    q = (y / x) & 0xffff;
    y %= x;
    t1 += q * t0;
    t1 &= 0xffff;
  }

  return (1 - t1) & 0xffff;
}

function mul(x, y) {
  x &= 0xffff;
  y &= 0xffff;

  if (y === 0)
    return (1 - x) & 0xffff;

  if (x === 0)
    return (1 - y) & 0xffff;

  const t32 = (x * y) >>> 0;

  x = t32 & 0xffff;
  y = t32 >>> 16;

  if (x < y)
    return (x - y + 1) & 0xffff;

  return (x - y) & 0xffff;
}

function readU16(data, pos) {
  return data[pos++] * 0x100 + data[pos];
}

function writeU16(data, value, pos) {
  data[pos++] = value >>> 8;
  data[pos++] = value;
  return pos;
}

/*
 * Expose
 */

module.exports = IDEA;
