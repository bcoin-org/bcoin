/*!
 * twofish.js - twofish for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on golang/go:
 *   Copyright (c) 2009, The Go Authors. All rights reserved.
 *   https://github.com/golang/go
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/Twofish
 *   https://www.schneier.com/academic/twofish/
 *   https://github.com/golang/crypto/blob/master/twofish/twofish.go
 */

'use strict';

const assert = require('../../internal/assert');

/*
 * Constants
 */

const BLOCK_SIZE = 16;
const MDS_POLY = 0x169; // x^8 + x^6 + x^5 + x^3 + 1
const RS_POLY = 0x14d; // x^8 + x^6 + x^3 + x^2 + 1

const RS = [
  new Uint8Array([0x01, 0xa4, 0x55, 0x87, 0x5a, 0x58, 0xdb, 0x9e]),
  new Uint8Array([0xa4, 0x56, 0x82, 0xf3, 0x1e, 0xc6, 0x68, 0xe5]),
  new Uint8Array([0x02, 0xa1, 0xfc, 0xc1, 0x47, 0xae, 0x3d, 0x19]),
  new Uint8Array([0xa4, 0x55, 0x87, 0x5a, 0x58, 0xdb, 0x9e, 0x03])
];

const S0 = new Uint8Array([
  0xa9, 0x67, 0xb3, 0xe8, 0x04, 0xfd, 0xa3, 0x76,
  0x9a, 0x92, 0x80, 0x78, 0xe4, 0xdd, 0xd1, 0x38,
  0x0d, 0xc6, 0x35, 0x98, 0x18, 0xf7, 0xec, 0x6c,
  0x43, 0x75, 0x37, 0x26, 0xfa, 0x13, 0x94, 0x48,
  0xf2, 0xd0, 0x8b, 0x30, 0x84, 0x54, 0xdf, 0x23,
  0x19, 0x5b, 0x3d, 0x59, 0xf3, 0xae, 0xa2, 0x82,
  0x63, 0x01, 0x83, 0x2e, 0xd9, 0x51, 0x9b, 0x7c,
  0xa6, 0xeb, 0xa5, 0xbe, 0x16, 0x0c, 0xe3, 0x61,
  0xc0, 0x8c, 0x3a, 0xf5, 0x73, 0x2c, 0x25, 0x0b,
  0xbb, 0x4e, 0x89, 0x6b, 0x53, 0x6a, 0xb4, 0xf1,
  0xe1, 0xe6, 0xbd, 0x45, 0xe2, 0xf4, 0xb6, 0x66,
  0xcc, 0x95, 0x03, 0x56, 0xd4, 0x1c, 0x1e, 0xd7,
  0xfb, 0xc3, 0x8e, 0xb5, 0xe9, 0xcf, 0xbf, 0xba,
  0xea, 0x77, 0x39, 0xaf, 0x33, 0xc9, 0x62, 0x71,
  0x81, 0x79, 0x09, 0xad, 0x24, 0xcd, 0xf9, 0xd8,
  0xe5, 0xc5, 0xb9, 0x4d, 0x44, 0x08, 0x86, 0xe7,
  0xa1, 0x1d, 0xaa, 0xed, 0x06, 0x70, 0xb2, 0xd2,
  0x41, 0x7b, 0xa0, 0x11, 0x31, 0xc2, 0x27, 0x90,
  0x20, 0xf6, 0x60, 0xff, 0x96, 0x5c, 0xb1, 0xab,
  0x9e, 0x9c, 0x52, 0x1b, 0x5f, 0x93, 0x0a, 0xef,
  0x91, 0x85, 0x49, 0xee, 0x2d, 0x4f, 0x8f, 0x3b,
  0x47, 0x87, 0x6d, 0x46, 0xd6, 0x3e, 0x69, 0x64,
  0x2a, 0xce, 0xcb, 0x2f, 0xfc, 0x97, 0x05, 0x7a,
  0xac, 0x7f, 0xd5, 0x1a, 0x4b, 0x0e, 0xa7, 0x5a,
  0x28, 0x14, 0x3f, 0x29, 0x88, 0x3c, 0x4c, 0x02,
  0xb8, 0xda, 0xb0, 0x17, 0x55, 0x1f, 0x8a, 0x7d,
  0x57, 0xc7, 0x8d, 0x74, 0xb7, 0xc4, 0x9f, 0x72,
  0x7e, 0x15, 0x22, 0x12, 0x58, 0x07, 0x99, 0x34,
  0x6e, 0x50, 0xde, 0x68, 0x65, 0xbc, 0xdb, 0xf8,
  0xc8, 0xa8, 0x2b, 0x40, 0xdc, 0xfe, 0x32, 0xa4,
  0xca, 0x10, 0x21, 0xf0, 0xd3, 0x5d, 0x0f, 0x00,
  0x6f, 0x9d, 0x36, 0x42, 0x4a, 0x5e, 0xc1, 0xe0
]);

const S1 = new Uint8Array([
  0x75, 0xf3, 0xc6, 0xf4, 0xdb, 0x7b, 0xfb, 0xc8,
  0x4a, 0xd3, 0xe6, 0x6b, 0x45, 0x7d, 0xe8, 0x4b,
  0xd6, 0x32, 0xd8, 0xfd, 0x37, 0x71, 0xf1, 0xe1,
  0x30, 0x0f, 0xf8, 0x1b, 0x87, 0xfa, 0x06, 0x3f,
  0x5e, 0xba, 0xae, 0x5b, 0x8a, 0x00, 0xbc, 0x9d,
  0x6d, 0xc1, 0xb1, 0x0e, 0x80, 0x5d, 0xd2, 0xd5,
  0xa0, 0x84, 0x07, 0x14, 0xb5, 0x90, 0x2c, 0xa3,
  0xb2, 0x73, 0x4c, 0x54, 0x92, 0x74, 0x36, 0x51,
  0x38, 0xb0, 0xbd, 0x5a, 0xfc, 0x60, 0x62, 0x96,
  0x6c, 0x42, 0xf7, 0x10, 0x7c, 0x28, 0x27, 0x8c,
  0x13, 0x95, 0x9c, 0xc7, 0x24, 0x46, 0x3b, 0x70,
  0xca, 0xe3, 0x85, 0xcb, 0x11, 0xd0, 0x93, 0xb8,
  0xa6, 0x83, 0x20, 0xff, 0x9f, 0x77, 0xc3, 0xcc,
  0x03, 0x6f, 0x08, 0xbf, 0x40, 0xe7, 0x2b, 0xe2,
  0x79, 0x0c, 0xaa, 0x82, 0x41, 0x3a, 0xea, 0xb9,
  0xe4, 0x9a, 0xa4, 0x97, 0x7e, 0xda, 0x7a, 0x17,
  0x66, 0x94, 0xa1, 0x1d, 0x3d, 0xf0, 0xde, 0xb3,
  0x0b, 0x72, 0xa7, 0x1c, 0xef, 0xd1, 0x53, 0x3e,
  0x8f, 0x33, 0x26, 0x5f, 0xec, 0x76, 0x2a, 0x49,
  0x81, 0x88, 0xee, 0x21, 0xc4, 0x1a, 0xeb, 0xd9,
  0xc5, 0x39, 0x99, 0xcd, 0xad, 0x31, 0x8b, 0x01,
  0x18, 0x23, 0xdd, 0x1f, 0x4e, 0x2d, 0xf9, 0x48,
  0x4f, 0xf2, 0x65, 0x8e, 0x78, 0x5c, 0x58, 0x19,
  0x8d, 0xe5, 0x98, 0x57, 0x67, 0x7f, 0x05, 0x64,
  0xaf, 0x63, 0xb6, 0xfe, 0xf5, 0xb7, 0x3c, 0xa5,
  0xce, 0xe9, 0x68, 0x44, 0xe0, 0x4d, 0x43, 0x69,
  0x29, 0x2e, 0xac, 0x15, 0x59, 0xa8, 0x0a, 0x9e,
  0x6e, 0x47, 0xdf, 0x34, 0x35, 0x6a, 0xcf, 0xdc,
  0x22, 0xc9, 0xc0, 0x9b, 0x89, 0xd4, 0xed, 0xab,
  0x12, 0xa2, 0x0d, 0x52, 0xbb, 0x02, 0x2f, 0xa9,
  0xd7, 0x61, 0x1e, 0xb4, 0x50, 0x04, 0xf6, 0xc2,
  0x16, 0x25, 0x86, 0x56, 0x55, 0x09, 0xbe, 0x91
]);

/**
 * Twofish
 */

class Twofish {
  constructor(bits = 256) {
    assert((bits >>> 0) === bits);
    assert(bits === 128 || bits === 192 || bits === 256);

    this.bits = bits;

    this.S = [
      new Uint32Array(256),
      new Uint32Array(256),
      new Uint32Array(256),
      new Uint32Array(256)
    ];

    this.k = new Uint32Array(40);
  }

  get blockSize() {
    return BLOCK_SIZE;
  }

  init(key) {
    assert(Buffer.isBuffer(key));

    const keylen = key.length;

    if (keylen !== 16 && keylen !== 24 && keylen !== 32)
      throw new Error('Invalid key size.');

    if (keylen !== (this.bits >>> 3))
      throw new Error('Invalid key size.');

    // k is the number of 64 bit words in key.
    const k = keylen >>> 3;

    // Create the S[..] words.
    const W = new Uint8Array(4 * 4);

    for (let i = 0; i < k; i++) {
      for (let j = 0; j < 4; j++) {
        for (let k = 0; k < 8; k++)
          W[4 * i + j] ^= gfMul(key[8 * i + k], RS[j][k], RS_POLY);
      }
    }

    // Calculate subkeys.
    const tmp = new Uint8Array(4);

    for (let i = 0; i < 20; i++) {
      for (let j = 0; j < 4; j++)
        tmp[j] = 2 * i;

      const A = h(tmp, key, 0);

      for (let j = 0; j < 4; j++)
        tmp[j] = 2 * i + 1;

      const B = rol32(h(tmp, key, 1), 8);

      this.k[2 * i + 0] = A + B;
      this.k[2 * i + 1] = rol32(2 * B + A, 9);
    }

    // Calculate sboxes.
    switch (k) {
      case 2:
        for (let i = 0; i < 256; i++) {
          this.S[0][i] = mdsMul(S1[S0[S0[i] ^ W[0]] ^ W[4]], 0);
          this.S[1][i] = mdsMul(S0[S0[S1[i] ^ W[1]] ^ W[5]], 1);
          this.S[2][i] = mdsMul(S1[S1[S0[i] ^ W[2]] ^ W[6]], 2);
          this.S[3][i] = mdsMul(S0[S1[S1[i] ^ W[3]] ^ W[7]], 3);
        }
        break;
      case 3:
        for (let i = 0; i < 256; i++) {
          this.S[0][i] = mdsMul(S1[S0[S0[S1[i] ^ W[0]] ^ W[4]] ^ W[8]], 0);
          this.S[1][i] = mdsMul(S0[S0[S1[S1[i] ^ W[1]] ^ W[5]] ^ W[9]], 1);
          this.S[2][i] = mdsMul(S1[S1[S0[S0[i] ^ W[2]] ^ W[6]] ^ W[10]], 2);
          this.S[3][i] = mdsMul(S0[S1[S1[S0[i] ^ W[3]] ^ W[7]] ^ W[11]], 3);
        }
        break;
      case 4:
        for (let i = 0; i < 256; i++) {
          this.S[0][i] =
            mdsMul(S1[S0[S0[S1[S1[i] ^ W[0]] ^ W[4]] ^ W[8]] ^ W[12]], 0);
          this.S[1][i] =
            mdsMul(S0[S0[S1[S1[S0[i] ^ W[1]] ^ W[5]] ^ W[9]] ^ W[13]], 1);
          this.S[2][i] =
            mdsMul(S1[S1[S0[S0[S0[i] ^ W[2]] ^ W[6]] ^ W[10]] ^ W[14]], 2);
          this.S[3][i] =
            mdsMul(S0[S1[S1[S0[S1[i] ^ W[3]] ^ W[7]] ^ W[11]] ^ W[15]], 3);
        }
        break;
      default:
        throw new Error('unreachable');
    }

    return this;
  }

  encrypt(output, opos, input, ipos) {
    const k = this.k;
    const S0 = this.S[0];
    const S1 = this.S[1];
    const S2 = this.S[2];
    const S3 = this.S[3];

    // Load input.
    let ia = readU32(input, ipos + 0);
    let ib = readU32(input, ipos + 4);
    let ic = readU32(input, ipos + 8);
    let id = readU32(input, ipos + 12);
    let t1, t2;

    // Pre-whitening.
    ia ^= this.k[0];
    ib ^= this.k[1];
    ic ^= this.k[2];
    id ^= this.k[3];

    for (let i = 0; i < 8; i++) {
      const p = 8 + i * 4;

      t2 = S1[(ib >>>  0) & 0xff]
         ^ S2[(ib >>>  8) & 0xff]
         ^ S3[(ib >>> 16) & 0xff]
         ^ S0[(ib >>> 24) & 0xff];

      t1 = S0[(ia >>>  0) & 0xff]
         ^ S1[(ia >>>  8) & 0xff]
         ^ S2[(ia >>> 16) & 0xff]
         ^ S3[(ia >>> 24) & 0xff];

      t1 += t2;

      ic = ror32(ic ^ (t1 + k[p + 0]), 1);
      id = rol32(id, 1) ^ (t2 + t1 + k[p + 1]);

      t2 = S1[(id >>>  0) & 0xff]
         ^ S2[(id >>>  8) & 0xff]
         ^ S3[(id >>> 16) & 0xff]
         ^ S0[(id >>> 24) & 0xff];

      t1 = S0[(ic >>>  0) & 0xff]
         ^ S1[(ic >>>  8) & 0xff]
         ^ S2[(ic >>> 16) & 0xff]
         ^ S3[(ic >>> 24) & 0xff];

      t1 += t2;

      ia = ror32(ia ^ (t1 + k[p + 2]), 1);
      ib = rol32(ib, 1) ^ (t2 + t1 + k[p + 3]);
    }

    // Output with "undo last swap".
    const ta = ic ^ this.k[4];
    const tb = id ^ this.k[5];
    const tc = ia ^ this.k[6];
    const td = ib ^ this.k[7];

    writeU32(output, ta, opos + 0);
    writeU32(output, tb, opos + 4);
    writeU32(output, tc, opos + 8);
    writeU32(output, td, opos + 12);

    return this;
  }

  decrypt(output, opos, input, ipos) {
    const k = this.k;
    const S0 = this.S[0];
    const S1 = this.S[1];
    const S2 = this.S[2];
    const S3 = this.S[3];

    // Load input.
    const ta = readU32(input, ipos + 0);
    const tb = readU32(input, ipos + 4);
    const tc = readU32(input, ipos + 8);
    const td = readU32(input, ipos + 12);

    // Undo undo final swap.
    let ia = tc ^ this.k[6];
    let ib = td ^ this.k[7];
    let ic = ta ^ this.k[4];
    let id = tb ^ this.k[5];
    let t1, t2;

    for (let i = 8; i > 0; i--) {
      const p = 4 + i * 4;

      t2 = S1[(id >>>  0) & 0xff]
         ^ S2[(id >>>  8) & 0xff]
         ^ S3[(id >>> 16) & 0xff]
         ^ S0[(id >>> 24) & 0xff];

      t1 = S0[(ic >>>  0) & 0xff]
         ^ S1[(ic >>>  8) & 0xff]
         ^ S2[(ic >>> 16) & 0xff]
         ^ S3[(ic >>> 24) & 0xff];

      t1 += t2;

      ia = rol32(ia, 1) ^ (t1 + k[p + 2]);
      ib = ror32(ib ^ (t2 + t1 + k[p + 3]), 1);

      t2 = S1[(ib >>>  0) & 0xff]
         ^ S2[(ib >>>  8) & 0xff]
         ^ S3[(ib >>> 16) & 0xff]
         ^ S0[(ib >>> 24) & 0xff];

      t1 = S0[(ia >>>  0) & 0xff]
         ^ S1[(ia >>>  8) & 0xff]
         ^ S2[(ia >>> 16) & 0xff]
         ^ S3[(ia >>> 24) & 0xff];

      t1 += t2;

      ic = rol32(ic, 1) ^ (t1 + k[p + 0]);
      id = ror32(id ^ (t2 + t1 + k[p + 1]), 1);
    }

    // Undo pre-whitening.
    ia ^= this.k[0];
    ib ^= this.k[1];
    ic ^= this.k[2];
    id ^= this.k[3];

    writeU32(output, ia, opos + 0);
    writeU32(output, ib, opos + 4);
    writeU32(output, ic, opos + 8);
    writeU32(output, id, opos + 12);

    return this;
  }

  destroy() {
    cleanse(this.S[0]);
    cleanse(this.S[1]);
    cleanse(this.S[2]);
    cleanse(this.S[3]);
    cleanse(this.k);
    return this;
  }
}

/*
 * Helpers
 */

function gfMul(a, b, p) {
  const B = new Uint32Array([0, b & 0xff]);
  const P = new Uint32Array([0, p >>> 0]);

  let res = 0;

  for (let i = 0; i < 7; i++) {
    res ^= B[a & 1];
    a >>>= 1;
    B[1] = P[B[1] >>> 7] ^ (B[1] << 1);
  }

  res ^= B[a & 1];

  return res & 0xff;
}

function mdsMul(v, col) {
  const x = v & 0xff;
  const y = gfMul(v, 0x5b, MDS_POLY);
  const z = gfMul(v, 0xef, MDS_POLY);

  switch (col) {
    case 0:
      return x | (y << 8) | (z << 16) | (z << 24);
    case 1:
      return z | (z << 8) | (y << 16) | (x << 24);
    case 2:
      return y | (z << 8) | (x << 16) | (z << 24);
    case 3:
      return y | (x << 8) | (z << 16) | (y << 24);
  }

  throw new Error('unreachable');
}

function h(v, key, off) {
  const y = new Uint8Array(4);

  for (let i = 0; i < 4; i++)
    y[i] = v[i];

  const k = key.length >>> 3;

  switch (k) {
    case 4:
      y[0] = S1[y[0]] ^ key[4 * (6 + off) + 0];
      y[1] = S0[y[1]] ^ key[4 * (6 + off) + 1];
      y[2] = S0[y[2]] ^ key[4 * (6 + off) + 2];
      y[3] = S1[y[3]] ^ key[4 * (6 + off) + 3];
      // fallthrough
    case 3:
      y[0] = S1[y[0]] ^ key[4 * (4 + off) + 0];
      y[1] = S1[y[1]] ^ key[4 * (4 + off) + 1];
      y[2] = S0[y[2]] ^ key[4 * (4 + off) + 2];
      y[3] = S0[y[3]] ^ key[4 * (4 + off) + 3];
      // fallthrough
    case 2:
      y[0] = S1[S0[S0[y[0]]
           ^ key[4 * (2 + off) + 0]]
           ^ key[4 * (0 + off) + 0]];
      y[1] = S0[S0[S1[y[1]]
           ^ key[4 * (2 + off) + 1]]
           ^ key[4 * (0 + off) + 1]];
      y[2] = S1[S1[S0[y[2]]
           ^ key[4 * (2 + off) + 2]]
           ^ key[4 * (0 + off) + 2]];
      y[3] = S0[S1[S1[y[3]]
           ^ key[4 * (2 + off) + 3]]
           ^ key[4 * (0 + off) + 3]];
      break;
    default:
      throw new Error('Invalid key size.');
  }

  let mult = 0;

  for (let i = 0; i < 4; i++)
    mult ^= mdsMul(y[i], i);

  return mult >>> 0;
}

function rol32(x, y) {
  return (x << (y & 31)) | (x >>> (32 - (y & 31)));
}

function ror32(x, y) {
  return (x >>> (y & 31)) | (x << (32 - (y & 31)));
}

function cleanse(arr) {
  for (let i = 0; i < arr.length; i++)
    arr[i] = 0;
}

function readU32(data, off) {
  return (data[off++]
        + data[off++] * 0x100
        + data[off++] * 0x10000
        + data[off++] * 0x1000000);
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

module.exports = Twofish;
