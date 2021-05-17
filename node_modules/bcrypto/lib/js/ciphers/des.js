/*!
 * des.js - DES for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on indutny/des.js:
 *   Copyright (c) 2015, Fedor Indutny (MIT License).
 *   https://github.com/indutny/des.js
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/Data_Encryption_Standard
 *   https://github.com/indutny/des.js/tree/master/lib/des
 */

'use strict';

const assert = require('../../internal/assert');

/*
 * Constants
 */

const PC2 = new Uint8Array([
  // inL => outL
  0x0e, 0x0b, 0x11, 0x04, 0x1b, 0x17, 0x19, 0x00,
  0x0d, 0x16, 0x07, 0x12, 0x05, 0x09, 0x10, 0x18,
  0x02, 0x14, 0x0c, 0x15, 0x01, 0x08, 0x0f, 0x1a,

  // inR => outR
  0x0f, 0x04, 0x19, 0x13, 0x09, 0x01, 0x1a, 0x10,
  0x05, 0x0b, 0x17, 0x08, 0x0c, 0x07, 0x11, 0x00,
  0x16, 0x03, 0x0a, 0x0e, 0x06, 0x14, 0x1b, 0x18
]);

const S = new Uint8Array([
  0x0e, 0x00, 0x04, 0x0f, 0x0d, 0x07, 0x01, 0x04,
  0x02, 0x0e, 0x0f, 0x02, 0x0b, 0x0d, 0x08, 0x01,
  0x03, 0x0a, 0x0a, 0x06, 0x06, 0x0c, 0x0c, 0x0b,
  0x05, 0x09, 0x09, 0x05, 0x00, 0x03, 0x07, 0x08,
  0x04, 0x0f, 0x01, 0x0c, 0x0e, 0x08, 0x08, 0x02,
  0x0d, 0x04, 0x06, 0x09, 0x02, 0x01, 0x0b, 0x07,
  0x0f, 0x05, 0x0c, 0x0b, 0x09, 0x03, 0x07, 0x0e,
  0x03, 0x0a, 0x0a, 0x00, 0x05, 0x06, 0x00, 0x0d,

  0x0f, 0x03, 0x01, 0x0d, 0x08, 0x04, 0x0e, 0x07,
  0x06, 0x0f, 0x0b, 0x02, 0x03, 0x08, 0x04, 0x0e,
  0x09, 0x0c, 0x07, 0x00, 0x02, 0x01, 0x0d, 0x0a,
  0x0c, 0x06, 0x00, 0x09, 0x05, 0x0b, 0x0a, 0x05,
  0x00, 0x0d, 0x0e, 0x08, 0x07, 0x0a, 0x0b, 0x01,
  0x0a, 0x03, 0x04, 0x0f, 0x0d, 0x04, 0x01, 0x02,
  0x05, 0x0b, 0x08, 0x06, 0x0c, 0x07, 0x06, 0x0c,
  0x09, 0x00, 0x03, 0x05, 0x02, 0x0e, 0x0f, 0x09,

  0x0a, 0x0d, 0x00, 0x07, 0x09, 0x00, 0x0e, 0x09,
  0x06, 0x03, 0x03, 0x04, 0x0f, 0x06, 0x05, 0x0a,
  0x01, 0x02, 0x0d, 0x08, 0x0c, 0x05, 0x07, 0x0e,
  0x0b, 0x0c, 0x04, 0x0b, 0x02, 0x0f, 0x08, 0x01,
  0x0d, 0x01, 0x06, 0x0a, 0x04, 0x0d, 0x09, 0x00,
  0x08, 0x06, 0x0f, 0x09, 0x03, 0x08, 0x00, 0x07,
  0x0b, 0x04, 0x01, 0x0f, 0x02, 0x0e, 0x0c, 0x03,
  0x05, 0x0b, 0x0a, 0x05, 0x0e, 0x02, 0x07, 0x0c,

  0x07, 0x0d, 0x0d, 0x08, 0x0e, 0x0b, 0x03, 0x05,
  0x00, 0x06, 0x06, 0x0f, 0x09, 0x00, 0x0a, 0x03,
  0x01, 0x04, 0x02, 0x07, 0x08, 0x02, 0x05, 0x0c,
  0x0b, 0x01, 0x0c, 0x0a, 0x04, 0x0e, 0x0f, 0x09,
  0x0a, 0x03, 0x06, 0x0f, 0x09, 0x00, 0x00, 0x06,
  0x0c, 0x0a, 0x0b, 0x01, 0x07, 0x0d, 0x0d, 0x08,
  0x0f, 0x09, 0x01, 0x04, 0x03, 0x05, 0x0e, 0x0b,
  0x05, 0x0c, 0x02, 0x07, 0x08, 0x02, 0x04, 0x0e,

  0x02, 0x0e, 0x0c, 0x0b, 0x04, 0x02, 0x01, 0x0c,
  0x07, 0x04, 0x0a, 0x07, 0x0b, 0x0d, 0x06, 0x01,
  0x08, 0x05, 0x05, 0x00, 0x03, 0x0f, 0x0f, 0x0a,
  0x0d, 0x03, 0x00, 0x09, 0x0e, 0x08, 0x09, 0x06,
  0x04, 0x0b, 0x02, 0x08, 0x01, 0x0c, 0x0b, 0x07,
  0x0a, 0x01, 0x0d, 0x0e, 0x07, 0x02, 0x08, 0x0d,
  0x0f, 0x06, 0x09, 0x0f, 0x0c, 0x00, 0x05, 0x09,
  0x06, 0x0a, 0x03, 0x04, 0x00, 0x05, 0x0e, 0x03,

  0x0c, 0x0a, 0x01, 0x0f, 0x0a, 0x04, 0x0f, 0x02,
  0x09, 0x07, 0x02, 0x0c, 0x06, 0x09, 0x08, 0x05,
  0x00, 0x06, 0x0d, 0x01, 0x03, 0x0d, 0x04, 0x0e,
  0x0e, 0x00, 0x07, 0x0b, 0x05, 0x03, 0x0b, 0x08,
  0x09, 0x04, 0x0e, 0x03, 0x0f, 0x02, 0x05, 0x0c,
  0x02, 0x09, 0x08, 0x05, 0x0c, 0x0f, 0x03, 0x0a,
  0x07, 0x0b, 0x00, 0x0e, 0x04, 0x01, 0x0a, 0x07,
  0x01, 0x06, 0x0d, 0x00, 0x0b, 0x08, 0x06, 0x0d,

  0x04, 0x0d, 0x0b, 0x00, 0x02, 0x0b, 0x0e, 0x07,
  0x0f, 0x04, 0x00, 0x09, 0x08, 0x01, 0x0d, 0x0a,
  0x03, 0x0e, 0x0c, 0x03, 0x09, 0x05, 0x07, 0x0c,
  0x05, 0x02, 0x0a, 0x0f, 0x06, 0x08, 0x01, 0x06,
  0x01, 0x06, 0x04, 0x0b, 0x0b, 0x0d, 0x0d, 0x08,
  0x0c, 0x01, 0x03, 0x04, 0x07, 0x0a, 0x0e, 0x07,
  0x0a, 0x09, 0x0f, 0x05, 0x06, 0x00, 0x08, 0x0f,
  0x00, 0x0e, 0x05, 0x02, 0x09, 0x03, 0x02, 0x0c,

  0x0d, 0x01, 0x02, 0x0f, 0x08, 0x0d, 0x04, 0x08,
  0x06, 0x0a, 0x0f, 0x03, 0x0b, 0x07, 0x01, 0x04,
  0x0a, 0x0c, 0x09, 0x05, 0x03, 0x06, 0x0e, 0x0b,
  0x05, 0x00, 0x00, 0x0e, 0x0c, 0x09, 0x07, 0x02,
  0x07, 0x02, 0x0b, 0x01, 0x04, 0x0e, 0x01, 0x07,
  0x09, 0x04, 0x0c, 0x0a, 0x0e, 0x08, 0x02, 0x0d,
  0x00, 0x0f, 0x06, 0x0c, 0x0a, 0x09, 0x0d, 0x00,
  0x0f, 0x03, 0x03, 0x05, 0x05, 0x06, 0x08, 0x0b
]);

const PERMUTE = new Uint8Array([
  0x10, 0x19, 0x0c, 0x0b, 0x03, 0x14, 0x04, 0x0f,
  0x1f, 0x11, 0x09, 0x06, 0x1b, 0x0e, 0x01, 0x16,
  0x1e, 0x18, 0x08, 0x12, 0x00, 0x05, 0x1d, 0x17,
  0x0d, 0x13, 0x02, 0x1a, 0x0a, 0x15, 0x1c, 0x07
]);

const SHIFT = new Uint8Array([
  0x01, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
  0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x01
]);

/**
 * DES
 */

class DES {
  constructor() {
    this.block = new Uint32Array(2);
    this.keys = new Uint32Array(32);
  }

  get blockSize() {
    return 8;
  }

  init(key) {
    assert(Buffer.isBuffer(key));
    assert(key.length === 8);
    return this.derive(key);
  }

  encrypt(output, opos, input, ipos) {
    return this.crypt(output, opos, input, ipos, true);
  }

  decrypt(output, opos, input, ipos) {
    return this.crypt(output, opos, input, ipos, false);
  }

  destroy() {
    for (let i = 0; i < 2; i++)
      this.block[i] = 0;

    for (let i = 0; i < 32; i++)
      this.keys[i] = 0;

    return this;
  }

  derive(key) {
    let kL = readU32(key, 0);
    let kR = readU32(key, 4);

    pc1(kL, kR, this.block, 0);
    kL = this.block[0];
    kR = this.block[1];

    for (let i = 0; i < 32; i += 2) {
      const shift = SHIFT[i >>> 1];

      kL = r28shl(kL, shift);
      kR = r28shl(kR, shift);

      pc2(kL, kR, this.keys, i);
    }

    return this;
  }

  crypt(output, opos, input, ipos, encrypt) {
    let l = readU32(input, ipos);
    let r = readU32(input, ipos + 4);

    // Initial Permutation
    ip(l, r, this.block, 0);

    l = this.block[0];
    r = this.block[1];

    if (encrypt)
      this.encipher(l, r, this.block, 0);
    else
      this.decipher(l, r, this.block, 0);

    l = this.block[0];
    r = this.block[1];

    writeU32(output, l, opos);
    writeU32(output, r, opos + 4);

    return this;
  }

  encipher(lStart, rStart, out, off) {
    let l = lStart;
    let r = rStart;

    // Apply f() x16 times
    for (let i = 0; i < 32; i += 2) {
      let keyL = this.keys[i];
      let keyR = this.keys[i + 1];

      // f(r, k)
      expand(r, this.block, 0);

      keyL ^= this.block[0];
      keyR ^= this.block[1];

      const s = substitute(keyL, keyR);
      const f = permute(s);
      const t = r;

      r = (l ^ f) >>> 0;
      l = t;
    }

    // Reverse Initial Permutation
    rip(r, l, out, off);

    return this;
  }

  decipher(lStart, rStart, out, off) {
    let l = rStart;
    let r = lStart;

    // Apply f() x16 times
    for (let i = 32 - 2; i >= 0; i -= 2) {
      let keyL = this.keys[i];
      let keyR = this.keys[i + 1];

      // f(r, k)
      expand(l, this.block, 0);

      keyL ^= this.block[0];
      keyR ^= this.block[1];

      const s = substitute(keyL, keyR);
      const f = permute(s);
      const t = l;

      l = (r ^ f) >>> 0;
      r = t;
    }

    // Reverse Initial Permutation
    rip(l, r, out, off);

    return this;
  }
}

/**
 * EDE
 */

class EDE {
  constructor() {
    this.x = new DES();
    this.y = new DES();
  }

  get blockSize() {
    return 8;
  }

  init(key) {
    assert(Buffer.isBuffer(key));
    assert(key.length === 16);

    const k1 = key.slice(0, 8);
    const k2 = key.slice(8, 16);

    this.x.init(k1);
    this.y.init(k2);

    return this;
  }

  encrypt(output, opos, input, ipos) {
    this.x.encrypt(output, opos, input, ipos);
    this.y.decrypt(output, opos, output, opos);
    this.x.encrypt(output, opos, output, opos);
    return this;
  }

  decrypt(output, opos, input, ipos) {
    this.x.decrypt(output, opos, input, ipos);
    this.y.encrypt(output, opos, output, opos);
    this.x.decrypt(output, opos, output, opos);
    return this;
  }

  destroy() {
    this.x.destroy();
    this.y.destroy();
    return this;
  }
}

/**
 * EDE3
 */

class EDE3 {
  constructor() {
    this.x = new DES();
    this.y = new DES();
    this.z = new DES();
  }

  get blockSize() {
    return 8;
  }

  init(key) {
    assert(Buffer.isBuffer(key));
    assert(key.length === 24);

    const k1 = key.slice(0, 8);
    const k2 = key.slice(8, 16);
    const k3 = key.slice(16, 24);

    this.x.init(k1);
    this.y.init(k2);
    this.z.init(k3);

    return this;
  }

  encrypt(output, opos, input, ipos) {
    this.x.encrypt(output, opos, input, ipos);
    this.y.decrypt(output, opos, output, opos);
    this.z.encrypt(output, opos, output, opos);
    return this;
  }

  decrypt(output, opos, input, ipos) {
    this.z.decrypt(output, opos, input, ipos);
    this.y.encrypt(output, opos, output, opos);
    this.x.decrypt(output, opos, output, opos);
    return this;
  }

  destroy() {
    this.x.destroy();
    this.y.destroy();
    this.z.destroy();
    return this;
  }
}

/*
 * Helpers
 */

function ip(inL, inR, out, off) {
  let outL = 0;
  let outR = 0;

  for (let i = 6; i >= 0; i -= 2) {
    for (let j = 0; j <= 24; j += 8) {
      outL <<= 1;
      outL |= (inR >>> (j + i)) & 1;
    }

    for (let j = 0; j <= 24; j += 8) {
      outL <<= 1;
      outL |= (inL >>> (j + i)) & 1;
    }
  }

  for (let i = 6; i >= 0; i -= 2) {
    for (let j = 1; j <= 25; j += 8) {
      outR <<= 1;
      outR |= (inR >>> (j + i)) & 1;
    }

    for (let j = 1; j <= 25; j += 8) {
      outR <<= 1;
      outR |= (inL >>> (j + i)) & 1;
    }
  }

  out[off + 0] = outL >>> 0;
  out[off + 1] = outR >>> 0;
}

function rip(inL, inR, out, off) {
  let outL = 0;
  let outR = 0;

  for (let i = 0; i < 4; i++) {
    for (let j = 24; j >= 0; j -= 8) {
      outL <<= 1;
      outL |= (inR >>> (j + i)) & 1;
      outL <<= 1;
      outL |= (inL >>> (j + i)) & 1;
    }
  }

  for (let i = 4; i < 8; i++) {
    for (let j = 24; j >= 0; j -= 8) {
      outR <<= 1;
      outR |= (inR >>> (j + i)) & 1;
      outR <<= 1;
      outR |= (inL >>> (j + i)) & 1;
    }
  }

  out[off + 0] = outL >>> 0;
  out[off + 1] = outR >>> 0;
}

function pc1(inL, inR, out, off) {
  let outL = 0;
  let outR = 0;

  // 7, 15, 23, 31, 39, 47, 55, 63
  // 6, 14, 22, 30, 39, 47, 55, 63
  // 5, 13, 21, 29, 39, 47, 55, 63
  // 4, 12, 20, 28
  for (let i = 7; i >= 5; i--) {
    for (let j = 0; j <= 24; j += 8) {
      outL <<= 1;
      outL |= (inR >> (j + i)) & 1;
    }

    for (let j = 0; j <= 24; j += 8) {
      outL <<= 1;
      outL |= (inL >> (j + i)) & 1;
    }
  }

  for (let j = 0; j <= 24; j += 8) {
    outL <<= 1;
    outL |= (inR >> (j + 4)) & 1;
  }

  // 1, 9, 17, 25, 33, 41, 49, 57
  // 2, 10, 18, 26, 34, 42, 50, 58
  // 3, 11, 19, 27, 35, 43, 51, 59
  // 36, 44, 52, 60
  for (let i = 1; i <= 3; i++) {
    for (let j = 0; j <= 24; j += 8) {
      outR <<= 1;
      outR |= (inR >> (j + i)) & 1;
    }

    for (let j = 0; j <= 24; j += 8) {
      outR <<= 1;
      outR |= (inL >> (j + i)) & 1;
    }
  }

  for (let j = 0; j <= 24; j += 8) {
    outR <<= 1;
    outR |= (inL >> (j + 4)) & 1;
  }

  out[off + 0] = outL >>> 0;
  out[off + 1] = outR >>> 0;
}

function r28shl(x, b) {
  return ((x << b) & 0xfffffff) | (x >>> (28 - b));
}

function pc2(inL, inR, out, off) {
  let outL = 0;
  let outR = 0;
  let i = 0;

  for (; i < 24; i++) {
    outL <<= 1;
    outL |= (inL >>> PC2[i]) & 1;
  }

  for (; i < 48; i++) {
    outR <<= 1;
    outR |= (inR >>> PC2[i]) & 1;
  }

  out[off + 0] = outL >>> 0;
  out[off + 1] = outR >>> 0;
}

function expand(r, out, off) {
  let outL = 0;
  let outR = 0;

  outL = ((r & 1) << 5) | (r >>> 27);

  for (let i = 23; i >= 15; i -= 4) {
    outL <<= 6;
    outL |= (r >>> i) & 0x3f;
  }

  for (let i = 11; i >= 3; i -= 4) {
    outR |= (r >>> i) & 0x3f;
    outR <<= 6;
  }

  outR |= ((r & 0x1f) << 1) | (r >>> 31);

  out[off + 0] = outL >>> 0;
  out[off + 1] = outR >>> 0;
}

function substitute(inL, inR) {
  let s = 0;

  for (let i = 0; i < 4; i++) {
    const b = (inL >>> (18 - i * 6)) & 0x3f;

    s = (s << 4) | S[i * 0x40 + b];
  }

  for (let i = 0; i < 4; i++) {
    const b = (inR >>> (18 - i * 6)) & 0x3f;

    s = (s << 4) | S[4 * 0x40 + i * 0x40 + b];
  }

  return s >>> 0;
}

function permute(s) {
  let f = 0;

  for (let i = 0; i < 32; i++) {
    f <<= 1;
    f |= (s >>> PERMUTE[i]) & 1;
  }

  return f >>> 0;
}

function readU32(data, off) {
  return (data[off++] * 0x1000000
        + data[off++] * 0x10000
        + data[off++] * 0x100
        + data[off]);
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

exports.DES = DES;
exports.EDE = EDE;
exports.EDE3 = EDE3;
