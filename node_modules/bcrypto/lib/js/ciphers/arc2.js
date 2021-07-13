/*!
 * arc2.js - ARC2 for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on golang/go:
 *   Copyright (c) 2009, The Go Authors. All rights reserved.
 *   https://github.com/golang/go
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/RC2
 *   https://github.com/golang/crypto/blob/master/pkcs12/internal/rc2/rc2.go
 *   https://en.wikipedia.org/wiki/RC2
 *   https://www.ietf.org/rfc/rfc2268.txt
 *   http://people.csail.mit.edu/rivest/pubs/KRRR98.pdf
 */

'use strict';

const assert = require('../../internal/assert');

/*
 * Constants
 */

const PI = new Uint8Array([
  0xd9, 0x78, 0xf9, 0xc4, 0x19, 0xdd, 0xb5, 0xed,
  0x28, 0xe9, 0xfd, 0x79, 0x4a, 0xa0, 0xd8, 0x9d,
  0xc6, 0x7e, 0x37, 0x83, 0x2b, 0x76, 0x53, 0x8e,
  0x62, 0x4c, 0x64, 0x88, 0x44, 0x8b, 0xfb, 0xa2,
  0x17, 0x9a, 0x59, 0xf5, 0x87, 0xb3, 0x4f, 0x13,
  0x61, 0x45, 0x6d, 0x8d, 0x09, 0x81, 0x7d, 0x32,
  0xbd, 0x8f, 0x40, 0xeb, 0x86, 0xb7, 0x7b, 0x0b,
  0xf0, 0x95, 0x21, 0x22, 0x5c, 0x6b, 0x4e, 0x82,
  0x54, 0xd6, 0x65, 0x93, 0xce, 0x60, 0xb2, 0x1c,
  0x73, 0x56, 0xc0, 0x14, 0xa7, 0x8c, 0xf1, 0xdc,
  0x12, 0x75, 0xca, 0x1f, 0x3b, 0xbe, 0xe4, 0xd1,
  0x42, 0x3d, 0xd4, 0x30, 0xa3, 0x3c, 0xb6, 0x26,
  0x6f, 0xbf, 0x0e, 0xda, 0x46, 0x69, 0x07, 0x57,
  0x27, 0xf2, 0x1d, 0x9b, 0xbc, 0x94, 0x43, 0x03,
  0xf8, 0x11, 0xc7, 0xf6, 0x90, 0xef, 0x3e, 0xe7,
  0x06, 0xc3, 0xd5, 0x2f, 0xc8, 0x66, 0x1e, 0xd7,
  0x08, 0xe8, 0xea, 0xde, 0x80, 0x52, 0xee, 0xf7,
  0x84, 0xaa, 0x72, 0xac, 0x35, 0x4d, 0x6a, 0x2a,
  0x96, 0x1a, 0xd2, 0x71, 0x5a, 0x15, 0x49, 0x74,
  0x4b, 0x9f, 0xd0, 0x5e, 0x04, 0x18, 0xa4, 0xec,
  0xc2, 0xe0, 0x41, 0x6e, 0x0f, 0x51, 0xcb, 0xcc,
  0x24, 0x91, 0xaf, 0x50, 0xa1, 0xf4, 0x70, 0x39,
  0x99, 0x7c, 0x3a, 0x85, 0x23, 0xb8, 0xb4, 0x7a,
  0xfc, 0x02, 0x36, 0x5b, 0x25, 0x55, 0x97, 0x31,
  0x2d, 0x5d, 0xfa, 0x98, 0xe3, 0x8a, 0x92, 0xae,
  0x05, 0xdf, 0x29, 0x10, 0x67, 0x6c, 0xba, 0xc9,
  0xd3, 0x00, 0xe6, 0xcf, 0xe1, 0x9e, 0xa8, 0x2c,
  0x63, 0x16, 0x01, 0x3f, 0x58, 0xe2, 0x89, 0xa9,
  0x0d, 0x38, 0x34, 0x1b, 0xab, 0x33, 0xff, 0xb0,
  0xbb, 0x48, 0x0c, 0x5f, 0xb9, 0xb1, 0xcd, 0x2e,
  0xc5, 0xf3, 0xdb, 0x47, 0xe5, 0xa5, 0x9c, 0x77,
  0x0a, 0xa6, 0x20, 0x68, 0xfe, 0x7f, 0xc1, 0xad
]);

/**
 * ARC2
 */

class ARC2 {
  constructor(bits = -1, ekb = -1) {
    assert(bits === -1 || (bits >>> 0) === bits);
    assert(ekb === -1 || (ekb >>> 0) === ekb);
    assert(bits === -1 || bits === 40 || bits === 64 || bits === 128);
    assert(ekb === -1 || ekb <= 1024);

    this.bits = bits;
    this.ekb = ekb;
    this.k = new Uint16Array(64);
    this.r = new Uint16Array(4);
  }

  get blockSize() {
    return 8;
  }

  init(key) {
    // Initialization logic borrowed from nettle.
    assert(Buffer.isBuffer(key));

    if (this.bits === -1)
      assert(key.length >= 1 && key.length <= 128);
    else
      assert(key.length * 8 === this.bits);

    let ekb = this.ekb;

    if (ekb === -1)
      ekb = key.length * 8;

    const L = Buffer.alloc(128, 0x00);

    for (let i = 0; i < key.length; i++)
      L[i] = key[i];

    for (let i = key.length; i < 128; i++)
      L[i] = PI[(L[i - key.length] + L[i - 1]) & 0xff];

    L[0] = PI[L[0]];

    if (ekb > 0 && ekb < 1024) {
      const len = (ekb + 7) >>> 3;

      let i = 128 - len;
      let x = PI[L[i] & (255 >> (7 & -ekb))];

      L[i] = x;

      while (i--) {
        x = PI[x ^ L[i + len]];
        L[i] = x;
      }
    }

    for (let i = 0; i < 64; i++)
      this.k[i] = readU16(L, i * 2);

    return this;
  }

  encrypt(output, opos, input, ipos) {
    const r = this.r;

    r[0] = readU16(input, ipos + 0);
    r[1] = readU16(input, ipos + 2);
    r[2] = readU16(input, ipos + 4);
    r[3] = readU16(input, ipos + 6);

    let j = 0;

    while (j <= 16) {
      // mix r[0]
      r[0] += this.k[j];
      r[0] += r[3] & r[2];
      r[0] += ~r[3] & r[1];
      r[0] = rotl16(r[0], 1);
      j += 1;

      // mix r[1]
      r[1] += this.k[j];
      r[1] += r[0] & r[3];
      r[1] += ~r[0] & r[2];
      r[1] = rotl16(r[1], 2);
      j += 1;

      // mix r[2]
      r[2] += this.k[j];
      r[2] += r[1] & r[0];
      r[2] += ~r[1] & r[3];
      r[2] = rotl16(r[2], 3);
      j += 1;

      // mix r[3]
      r[3] += this.k[j];
      r[3] += r[2] & r[1];
      r[3] += ~r[2] & r[0];
      r[3] = rotl16(r[3], 5);
      j += 1;
    }

    r[0] += this.k[r[3] & 63];
    r[1] += this.k[r[0] & 63];
    r[2] += this.k[r[1] & 63];
    r[3] += this.k[r[2] & 63];

    while (j <= 40) {
      // mix r[0]
      r[0] += this.k[j];
      r[0] += r[3] & r[2];
      r[0] += ~r[3] & r[1];
      r[0] = rotl16(r[0], 1);
      j += 1;

      // mix r[1]
      r[1] += this.k[j];
      r[1] += r[0] & r[3];
      r[1] += ~r[0] & r[2];
      r[1] = rotl16(r[1], 2);
      j += 1;

      // mix r[2]
      r[2] += this.k[j];
      r[2] += r[1] & r[0];
      r[2] += ~r[1] & r[3];
      r[2] = rotl16(r[2], 3);
      j += 1;

      // mix r[3]
      r[3] += this.k[j];
      r[3] += r[2] & r[1];
      r[3] += ~r[2] & r[0];
      r[3] = rotl16(r[3], 5);
      j += 1;
    }

    r[0] += this.k[r[3] & 63];
    r[1] += this.k[r[0] & 63];
    r[2] += this.k[r[1] & 63];
    r[3] += this.k[r[2] & 63];

    while (j <= 60) {
      // mix r[0]
      r[0] += this.k[j];
      r[0] += r[3] & r[2];
      r[0] += ~r[3] & r[1];
      r[0] = rotl16(r[0], 1);
      j += 1;

      // mix r[1]
      r[1] += this.k[j];
      r[1] += r[0] & r[3];
      r[1] += ~r[0] & r[2];
      r[1] = rotl16(r[1], 2);
      j += 1;

      // mix r[2]
      r[2] += this.k[j];
      r[2] += r[1] & r[0];
      r[2] += ~r[1] & r[3];
      r[2] = rotl16(r[2], 3);
      j += 1;

      // mix r[3]
      r[3] += this.k[j];
      r[3] += r[2] & r[1];
      r[3] += ~r[2] & r[0];
      r[3] = rotl16(r[3], 5);
      j += 1;
    }

    writeU16(output, r[0], opos + 0);
    writeU16(output, r[1], opos + 2);
    writeU16(output, r[2], opos + 4);
    writeU16(output, r[3], opos + 6);
  }

  decrypt(output, opos, input, ipos) {
    const r = this.r;

    r[0] = readU16(input, ipos + 0);
    r[1] = readU16(input, ipos + 2);
    r[2] = readU16(input, ipos + 4);
    r[3] = readU16(input, ipos + 6);

    let j = 63;

    while (j >= 44) {
      // unmix r[3]
      r[3] = rotl16(r[3], 16 - 5);
      r[3] -= this.k[j];
      r[3] -= r[2] & r[1];
      r[3] -= ~r[2] & r[0];
      j -= 1;

      // unmix r[2]
      r[2] = rotl16(r[2], 16 - 3);
      r[2] -= this.k[j];
      r[2] -= r[1] & r[0];
      r[2] -= ~r[1] & r[3];
      j -= 1;

      // unmix r[1]
      r[1] = rotl16(r[1], 16 - 2);
      r[1] -= this.k[j];
      r[1] -= r[0] & r[3];
      r[1] -= ~r[0] & r[2];
      j -= 1;

      // unmix r[0]
      r[0] = rotl16(r[0], 16 - 1);
      r[0] -= this.k[j];
      r[0] -= r[3] & r[2];
      r[0] -= ~r[3] & r[1];
      j -= 1;
    }

    r[3] -= this.k[r[2] & 63];
    r[2] -= this.k[r[1] & 63];
    r[1] -= this.k[r[0] & 63];
    r[0] -= this.k[r[3] & 63];

    while (j >= 20) {
      // unmix r[3]
      r[3] = rotl16(r[3], 16 - 5);
      r[3] -= this.k[j];
      r[3] -= r[2] & r[1];
      r[3] -= ~r[2] & r[0];
      j -= 1;

      // unmix r[2]
      r[2] = rotl16(r[2], 16 - 3);
      r[2] -= this.k[j];
      r[2] -= r[1] & r[0];
      r[2] -= ~r[1] & r[3];
      j -= 1;

      // unmix r[1]
      r[1] = rotl16(r[1], 16 - 2);
      r[1] -= this.k[j];
      r[1] -= r[0] & r[3];
      r[1] -= ~r[0] & r[2];
      j -= 1;

      // unmix r[0]
      r[0] = rotl16(r[0], 16 - 1);
      r[0] -= this.k[j];
      r[0] -= r[3] & r[2];
      r[0] -= ~r[3] & r[1];
      j -= 1;
    }

    r[3] -= this.k[r[2] & 63];
    r[2] -= this.k[r[1] & 63];
    r[1] -= this.k[r[0] & 63];
    r[0] -= this.k[r[3] & 63];

    while (j >= 0) {
      // unmix r[3]
      r[3] = rotl16(r[3], 16 - 5);
      r[3] -= this.k[j];
      r[3] -= r[2] & r[1];
      r[3] -= ~r[2] & r[0];
      j -= 1;

      // unmix r[2]
      r[2] = rotl16(r[2], 16 - 3);
      r[2] -= this.k[j];
      r[2] -= r[1] & r[0];
      r[2] -= ~r[1] & r[3];
      j -= 1;

      // unmix r[1]
      r[1] = rotl16(r[1], 16 - 2);
      r[1] -= this.k[j];
      r[1] -= r[0] & r[3];
      r[1] -= ~r[0] & r[2];
      j -= 1;

      // unmix r[0]
      r[0] = rotl16(r[0], 16 - 1);
      r[0] -= this.k[j];
      r[0] -= r[3] & r[2];
      r[0] -= ~r[3] & r[1];
      j -= 1;
    }

    writeU16(output, r[0], opos + 0);
    writeU16(output, r[1], opos + 2);
    writeU16(output, r[2], opos + 4);
    writeU16(output, r[3], opos + 6);
  }

  destroy() {
    for (let i = 0; i < 64; i++)
      this.k[i] = 0;

    for (let i = 0; i < 4; i++)
      this.r[i] = 0;

    return this;
  }
}

/*
 * Helpers
 */

function rotl16(x, b) {
  return (x >>> (16 - b)) | (x << b);
}

function readU16(data, pos) {
  return data[pos++] + data[pos] * 0x100;
}

function writeU16(data, value, pos) {
  data[pos++] = value;
  data[pos++] = value >>> 8;
  return pos;
}

/*
 * Expose
 */

module.exports = ARC2;
