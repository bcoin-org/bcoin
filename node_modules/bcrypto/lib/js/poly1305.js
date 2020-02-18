/*!
 * poly1305.js - poly1305 for bcrypto
 * Copyright (c) 2016-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');

/**
 * Poly1305
 * @see https://github.com/floodyberry/poly1305-donna
 * @see https://tools.ietf.org/html/rfc7539#section-2.5
 */

class Poly1305 {
  /**
   * Create a Poly1305 context.
   * @constructor
   */

  constructor() {
    this.r = new Uint16Array(10);
    this.h = new Uint16Array(10);
    this.pad = new Uint16Array(8);
    this.fin = 0;
    this.leftover = 0;
    this.buffer = Buffer.allocUnsafe(16);
  }

  /**
   * Initialize poly1305 with a key.
   * @param {Buffer} key
   */

  init(key) {
    assert(Buffer.isBuffer(key) && key.length >= 32);

    // r &= 0xffffffc0ffffffc0ffffffc0fffffff
    const t0 = readU16(key, 0);
    const t1 = readU16(key, 2);
    const t2 = readU16(key, 4);
    const t3 = readU16(key, 6);
    const t4 = readU16(key, 8);
    const t5 = readU16(key, 10);
    const t6 = readU16(key, 12);
    const t7 = readU16(key, 14);

    this.r[0] = t0 & 0x1fff;
    this.r[1] = ((t0 >>> 13) | (t1 << 3)) & 0x1fff;
    this.r[2] = ((t1 >>> 10) | (t2 << 6)) & 0x1f03;
    this.r[3] = ((t2 >>> 7) | (t3 << 9)) & 0x1fff;
    this.r[4] = ((t3 >>> 4) | (t4 << 12)) & 0x00ff;
    this.r[5] = (t4 >>> 1) & 0x1ffe;
    this.r[6] = ((t4 >>> 14) | (t5 << 2)) & 0x1fff;
    this.r[7] = ((t5 >>> 11) | (t6 << 5)) & 0x1f81;
    this.r[8] = ((t6 >>> 8) | (t7 << 8)) & 0x1fff;
    this.r[9] = (t7 >>> 5) & 0x007f;

    // h = 0
    for (let i = 0; i < 10; i++)
      this.h[i] = 0;

    // save pad for later
    for (let i = 0; i < 8; i++)
      this.pad[i] = readU16(key, 16 + (2 * i));

    this.leftover = 0;
    this.fin = 0;

    return this;
  }

  /**
   * Process 16 byte blocks.
   * @param {Buffer} data - Blocks.
   * @param {Number} bytes - Size.
   * @param {Number} m - Offset pointer.
   */

  blocks(data, bytes, m) {
    const hibit = this.fin ? 0 : (1 << 11); // 1 << 128
    const d = new Uint32Array(10);

    while (bytes >= 16) {
      // h += m[i]
      const t0 = readU16(data, m + 0);
      const t1 = readU16(data, m + 2);
      const t2 = readU16(data, m + 4);
      const t3 = readU16(data, m + 6);
      const t4 = readU16(data, m + 8);
      const t5 = readU16(data, m + 10);
      const t6 = readU16(data, m + 12);
      const t7 = readU16(data, m + 14);

      this.h[0] += t0 & 0x1fff;
      this.h[1] += ((t0 >>> 13) | (t1 << 3)) & 0x1fff;
      this.h[2] += ((t1 >>> 10) | (t2 << 6)) & 0x1fff;
      this.h[3] += ((t2 >>> 7) | (t3 << 9)) & 0x1fff;
      this.h[4] += ((t3 >>> 4) | (t4 << 12)) & 0x1fff;
      this.h[5] += ((t4 >>> 1)) & 0x1fff;
      this.h[6] += ((t4 >>> 14) | (t5 << 2)) & 0x1fff;
      this.h[7] += ((t5 >>> 11) | (t6 << 5)) & 0x1fff;
      this.h[8] += ((t6 >>> 8) | (t7 << 8)) & 0x1fff;
      this.h[9] += ((t7 >>> 5)) | hibit;

      // h *= r, (partial) h %= p
      let c = 0;
      for (let i = 0; i < 10; i++) {
        d[i] = c;

        for (let j = 0; j < 10; j++) {
          let a = this.h[j];

          if (j <= i)
            a *= this.r[i - j];
          else
            a *= 5 * this.r[i + 10 - j];

          d[i] += a;

          // Sum(h[i] * r[i] * 5) will overflow slightly
          // above 6 products with an unclamped r, so
          // carry at 5
          if (j === 4) {
            c = d[i] >>> 13;
            d[i] &= 0x1fff;
          }
        }

        c += d[i] >>> 13;
        d[i] &= 0x1fff;
      }

      c = (c << 2) + c; // c *= 5
      c += d[0];
      d[0] = (c & 0x1fff);
      c = c >>> 13;
      d[1] += c;

      for (let i = 0; i < 10; i++)
        this.h[i] = d[i];

      m += 16;
      bytes -= 16;
    }
  }

  /**
   * Update the MAC with data (will be
   * processed as 16 byte blocks).
   * @param {Buffer} data
   */

  update(data) {
    assert(Buffer.isBuffer(data));

    let bytes = data.length;
    let m = 0;

    // handle leftover
    if (this.leftover) {
      let want = 16 - this.leftover;

      if (want > bytes)
        want = bytes;

      for (let i = 0; i < want; i++)
        this.buffer[this.leftover + i] = data[m + i];

      bytes -= want;
      m += want;

      this.leftover += want;

      if (this.leftover < 16)
        return this;

      this.blocks(this.buffer, 16, 0);
      this.leftover = 0;
    }

    // process full blocks
    if (bytes >= 16) {
      const want = bytes & ~(16 - 1);
      this.blocks(data, want, m);
      m += want;
      bytes -= want;
    }

    // store leftover
    if (bytes) {
      for (let i = 0; i < bytes; i++)
        this.buffer[this.leftover + i] = data[m + i];
      this.leftover += bytes;
    }

    return this;
  }

  /**
   * Finalize and return a 16-byte MAC.
   * @returns {Buffer}
   */

  final() {
    const mac = Buffer.allocUnsafe(16);
    const g = new Uint16Array(10);

    // process the remaining block
    if (this.leftover) {
      let i = this.leftover;
      this.buffer[i++] = 1;
      for (; i < 16; i++)
        this.buffer[i] = 0;
      this.fin = 1;
      this.blocks(this.buffer, 16, 0);
    }

    // fully carry h
    let c = this.h[1] >>> 13;
    this.h[1] &= 0x1fff;
    for (let i = 2; i < 10; i++) {
      this.h[i] += c;
      c = this.h[i] >>> 13;
      this.h[i] &= 0x1fff;
    }
    this.h[0] += c * 5;
    c = this.h[0] >>> 13;
    this.h[0] &= 0x1fff;
    this.h[1] += c;
    c = this.h[1] >>> 13;
    this.h[1] &= 0x1fff;
    this.h[2] += c;

    // compute h + -p
    g[0] = this.h[0] + 5;
    c = g[0] >>> 13;
    g[0] &= 0x1fff;
    for (let i = 1; i < 10; i++) {
      g[i] = this.h[i] + c;
      c = g[i] >>> 13;
      g[i] &= 0x1fff;
    }

    // select h if h < p, or h + -p if h >= p
    let mask = (c ^ 1) - 1;
    for (let i = 0; i < 10; i++)
      g[i] &= mask;
    mask = ~mask;
    for (let i = 0; i < 10; i++)
      this.h[i] = (this.h[i] & mask) | g[i];

    // h = h % (2^128)
    this.h[0] = ((this.h[0]) | (this.h[1] << 13)) & 0xffff;
    this.h[1] = ((this.h[1] >>> 3) | (this.h[2] << 10)) & 0xffff;
    this.h[2] = ((this.h[2] >>> 6) | (this.h[3] << 7)) & 0xffff;
    this.h[3] = ((this.h[3] >>> 9) | (this.h[4] << 4)) & 0xffff;
    this.h[4] = ((this.h[4] >>> 12)
      | (this.h[5] << 1) | (this.h[6] << 14)) & 0xffff;
    this.h[5] = ((this.h[6] >>> 2) | (this.h[7] << 11)) & 0xffff;
    this.h[6] = ((this.h[7] >>> 5) | (this.h[8] << 8)) & 0xffff;
    this.h[7] = ((this.h[8] >>> 8) | (this.h[9] << 5)) & 0xffff;

    // mac = (h + pad) % (2^128)
    let f = this.h[0] + this.pad[0];
    this.h[0] = f;
    for (let i = 1; i < 8; i++) {
      f = this.h[i] + this.pad[i] + (f >>> 16);
      this.h[i] = f;
    }

    for (let i = 0; i < 8; i++)
      writeU16(mac, this.h[i], i * 2);

    // zero out the state
    for (let i = 0; i < 10; i++)
      this.h[i] = 0;

    for (let i = 0; i < 10; i++)
      this.r[i] = 0;

    for (let i = 0; i < 8; i++)
      this.pad[i] = 0;

    return mac;
  }

  /**
   * Return a MAC for a message and key.
   * @param {Buffer} msg
   * @param {Buffer} key
   * @returns {Buffer} MAC
   */

  static auth(msg, key) {
    const poly = new Poly1305();
    poly.init(key);
    poly.update(msg);
    return poly.final();
  }

  /**
   * Compare two MACs in constant time.
   * @param {Buffer} mac1
   * @param {Buffer} mac2
   * @returns {Boolean}
   */

  static verify(mac1, mac2) {
    assert(Buffer.isBuffer(mac1) && mac1.length === 16);
    assert(Buffer.isBuffer(mac2) && mac2.length === 16);

    let dif = 0;

    // Compare in constant time.
    for (let i = 0; i < 16; i++)
      dif |= mac1[i] ^ mac2[i];

    dif = (dif - 1) >>> 31;

    return (dif & 1) !== 0;
  }
}

Poly1305.native = 0;

/*
 * Helpers
 */

function readU16(data, off) {
  return data[off++] + data[off] * 0x100;
}

function writeU16(dst, num, off) {
  dst[off++] = num;
  dst[off++] = num >>> 8;
  return off;
}

/*
 * Expose
 */

module.exports = Poly1305;
