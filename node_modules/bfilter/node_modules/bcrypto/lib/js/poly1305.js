/*!
 * poly1305.js - poly1305 for bcrypto
 * Copyright (c) 2016-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on floodyberry/poly1305-donna:
 *   Placed into the public domain by Andrew Moon.
 *   https://github.com/floodyberry/poly1305-donna
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/Poly1305
 *   https://cr.yp.to/mac.html
 *   https://tools.ietf.org/html/rfc7539#section-2.5
 *   https://github.com/floodyberry/poly1305-donna/blob/master/poly1305-donna-16.h
 */

'use strict';

const assert = require('../internal/assert');

/**
 * Poly1305
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
    this.buffer = Buffer.alloc(16);
    this.fin = -1;
    this.leftover = 0;
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

    // Save pad for later.
    for (let i = 0; i < 8; i++)
      this.pad[i] = readU16(key, 16 + (2 * i));

    this.fin = 0;
    this.leftover = 0;

    return this;
  }

  /**
   * Process 16 byte blocks.
   * @private
   * @param {Buffer} data - Blocks.
   * @param {Number} bytes - Size.
   * @param {Number} m - Offset pointer.
   */

  _blocks(data, bytes, m) {
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

          // Sum(h[i] * r[i] * 5) will overflow
          // slightly above 6 products with an
          // unclamped r, so carry at 5.
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

    if (this.fin === -1)
      throw new Error('Context is not initialized.');

    let bytes = data.length;
    let m = 0;

    // Handle leftover.
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

      this._blocks(this.buffer, 16, 0);
      this.leftover = 0;
    }

    // Process full blocks.
    if (bytes >= 16) {
      const want = bytes & ~(16 - 1);

      this._blocks(data, want, m);

      m += want;
      bytes -= want;
    }

    // Store leftover.
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
    if (this.fin === -1)
      throw new Error('Context is not initialized.');

    const mac = Buffer.alloc(16);
    const g = new Uint16Array(10);

    // Process the remaining block.
    if (this.leftover) {
      let i = this.leftover;

      this.buffer[i++] = 1;

      for (; i < 16; i++)
        this.buffer[i] = 0;

      this.fin = 1;
      this._blocks(this.buffer, 16, 0);
    }

    // Fully carry h.
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

    // Compute h + -p.
    g[0] = this.h[0] + 5;
    c = g[0] >>> 13;
    g[0] &= 0x1fff;

    for (let i = 1; i < 10; i++) {
      g[i] = this.h[i] + c;
      c = g[i] >>> 13;
      g[i] &= 0x1fff;
    }

    // Select h if h < p, or h + -p if h >= p.
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

    // Zero out the state.
    this.destroy();

    return mac;
  }

  /**
   * Destroy the context.
   */

  destroy() {
    for (let i = 0; i < 10; i++) {
      this.r[i] = 0;
      this.h[i] = 0;
    }

    for (let i = 0; i < 8; i++)
      this.pad[i] = 0;

    for (let i = 0; i < 16; i++)
      this.buffer[i] = 0;

    this.fin = -1;
    this.leftover = 0;
  }

  /**
   * Finalize and verify MAC against tag.
   * @param {Buffer} tag
   * @returns {Boolean}
   */

  verify(tag) {
    assert(Buffer.isBuffer(tag));
    assert(tag.length === 16);

    const mac = this.final();

    let z = 0;

    for (let i = 0; i < 16; i++)
      z |= mac[i] ^ tag[i];

    return ((z - 1) >>> 31) !== 0;
  }
}

/*
 * Static
 */

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
