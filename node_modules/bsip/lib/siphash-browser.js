/*!
 * siphash.js - siphash for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');

/*
 * Constants
 */

const HI = 1 / 0x100000000;

/**
 * Javascript siphash 2-4 implementation.
 * @private
 * @param {Buffer} data
 * @param {Buffer} key - 128 bit key.
 * @returns {Array} [hi, lo]
 */

function _siphash(data, key) {
  assert(Buffer.isBuffer(data));
  assert(Buffer.isBuffer(key) && key.length >= 16);

  const blocks = data.length >>> 3;
  const c0 = new U64(0x736f6d65, 0x70736575);
  const c1 = new U64(0x646f7261, 0x6e646f6d);
  const c2 = new U64(0x6c796765, 0x6e657261);
  const c3 = new U64(0x74656462, 0x79746573);
  const f0 = new U64(data.length << 24, 0);
  const f1 = new U64(0, 0xff);
  const k0 = U64.fromRaw(key, 0);
  const k1 = U64.fromRaw(key, 8);

  // Init
  const v0 = c0.ixor(k0);
  const v1 = c1.ixor(k1);
  const v2 = c2.ixor(k0);
  const v3 = c3.ixor(k1);

  // Blocks
  let p = 0;
  for (let i = 0; i < blocks; i++) {
    const d = U64.fromRaw(data, p);
    p += 8;
    v3.ixor(d);
    sipround(v0, v1, v2, v3);
    sipround(v0, v1, v2, v3);
    v0.ixor(d);
  }

  switch (data.length & 7) {
    case 7:
      f0.hi |= data[p + 6] << 16;
    case 6:
      f0.hi |= data[p + 5] << 8;
    case 5:
      f0.hi |= data[p + 4];
    case 4:
      f0.lo |= data[p + 3] << 24;
    case 3:
      f0.lo |= data[p + 2] << 16;
    case 2:
      f0.lo |= data[p + 1] << 8;
    case 1:
      f0.lo |= data[p];
  }

  // Finalization
  v3.ixor(f0);
  sipround(v0, v1, v2, v3);
  sipround(v0, v1, v2, v3);
  v0.ixor(f0);
  v2.ixor(f1);
  sipround(v0, v1, v2, v3);
  sipround(v0, v1, v2, v3);
  sipround(v0, v1, v2, v3);
  sipround(v0, v1, v2, v3);
  v0.ixor(v1);
  v0.ixor(v2);
  v0.ixor(v3);

  return [v0.hi, v0.lo];
}

/**
 * Javascript siphash 2-4 implementation (64 bit ints).
 * @private
 * @param {Number} hi
 * @param {Number} lo
 * @param {Buffer} key - 128 bit key.
 * @returns {Array} [hi, lo]
 */

function _siphash64(hi, lo, key) {
  assert(typeof hi === 'number');
  assert(typeof lo === 'number');
  assert(Buffer.isBuffer(key) && key.length >= 16);

  const c0 = new U64(0x736f6d65, 0x70736575);
  const c1 = new U64(0x646f7261, 0x6e646f6d);
  const c2 = new U64(0x6c796765, 0x6e657261);
  const c3 = new U64(0x74656462, 0x79746573);
  const f0 = new U64(hi, lo);
  const f1 = new U64(0, 0xff);
  const k0 = U64.fromRaw(key, 0);
  const k1 = U64.fromRaw(key, 8);

  // Init
  const v0 = c0.ixor(k0);
  const v1 = c1.ixor(k1);
  const v2 = c2.ixor(k0);
  const v3 = c3.ixor(k1);

  // Finalization
  v3.ixor(f0);
  sipround(v0, v1, v2, v3);
  sipround(v0, v1, v2, v3);
  v0.ixor(f0);
  v2.ixor(f1);
  sipround(v0, v1, v2, v3);
  sipround(v0, v1, v2, v3);
  sipround(v0, v1, v2, v3);
  sipround(v0, v1, v2, v3);
  v0.ixor(v1);
  v0.ixor(v2);
  v0.ixor(v3);

  return [v0.hi, v0.lo];
}

/**
 * Javascript siphash 2-4 implementation
 * (64 bit ints with a 256 bit key).
 * @private
 * @param {Number} hi
 * @param {Number} lo
 * @param {Buffer} key - 128 bit key.
 * @returns {Array} [hi, lo]
 */

function _siphash64k256(hi, lo, key) {
  assert(typeof hi === 'number');
  assert(typeof lo === 'number');
  assert(Buffer.isBuffer(key) && key.length >= 32);

  const f0 = new U64(hi, lo);
  const f1 = new U64(0, 0xff);
  const k0 = U64.fromRaw(key, 0);
  const k1 = U64.fromRaw(key, 8);
  const k2 = U64.fromRaw(key, 16);
  const k3 = U64.fromRaw(key, 24);

  // Init
  const v0 = k0;
  const v1 = k1;
  const v2 = k2;
  const v3 = k3;

  // Finalization
  v3.ixor(f0);
  sipround(v0, v1, v2, v3);
  sipround(v0, v1, v2, v3);
  v0.ixor(f0);
  v2.ixor(f1);
  sipround(v0, v1, v2, v3);
  sipround(v0, v1, v2, v3);
  sipround(v0, v1, v2, v3);
  sipround(v0, v1, v2, v3);
  v0.ixor(v1);
  v0.ixor(v2);
  v0.ixor(v3);

  return [v0.hi, v0.lo];
}

/**
 * Javascript siphash 2-4 implementation.
 * Used by bitcoin for compact block relay.
 * @param {Buffer} data
 * @param {Buffer} key - 128 bit key.
 * @returns {Array} [hi, lo]
 */

function siphash(data, key) {
  return _siphash(data, key);
}

/**
 * Javascript siphash 2-4 implementation (32 bit ints).
 * Used by legacy cuckoo cycle.
 * @param {Number} num
 * @param {Buffer} key - 128 bit key.
 * @returns {Number}
 */

function siphash32(num, key) {
  return _siphash64(0, num, key)[1];
}

/**
 * Javascript siphash 2-4 implementation (64 bit ints).
 * Used by legacy cuckoo cycle.
 * @param {Number} hi
 * @param {Number} lo
 * @param {Buffer} key - 128 bit key.
 * @returns {Array} [hi, lo]
 */

function siphash64(hi, lo, key) {
  return _siphash64(hi, lo, key);
}

/**
 * Javascript siphash 2-4 implementation
 * (32 bit ints with a 256 bit key).
 * Used by cuckoo cycle.
 * @param {Number} num
 * @param {Buffer} key - 256 bit key.
 * @returns {Number}
 */

function siphash32k256(num, key) {
  return _siphash64k256(0, num, key)[1];
}

/**
 * Javascript siphash 2-4 implementation
 * (64 bit ints with a 256 bit key).
 * Used by cuckoo cycle.
 * @param {Number} hi
 * @param {Number} lo
 * @param {Buffer} key - 256 bit key.
 * @returns {Array} [hi, lo]
 */

function siphash64k256(hi, lo, key) {
  return _siphash64k256(hi, lo, key);
}

/**
 * Javascript siphash 2-4 implementation
 * plus 128 bit reduction by a modulus.
 * Used by the neutrino protocol.
 * @param {Buffer} data
 * @param {Buffer} key - 128 bit key.
 * @param {Number} mhi - Modulus hi bits.
 * @param {Number} mlo - Modulus lo bits.
 * @returns {Array} [hi, lo]
 */

function sipmod(data, key, mhi, mlo) {
  const [hi, lo] = _siphash(data, key);
  return reduce64(hi, lo, mhi, mlo);
}

/**
 * U64
 * @ignore
 */

class U64 {
  constructor(hi, lo) {
    this.hi = hi | 0;
    this.lo = lo | 0;
  }

  iadd(b) {
    const a = this;

    // Credit to @indutny for this method.
    const lo = (a.lo + b.lo) | 0;

    const s = lo >> 31;
    const as = a.lo >> 31;
    const bs = b.lo >> 31;

    const c = ((as & bs) | (~s & (as ^ bs))) & 1;

    const hi = ((a.hi + b.hi) | 0) + c;

    a.hi = hi | 0;
    a.lo = lo;

    return a;
  }

  ixor(b) {
    this.hi ^= b.hi;
    this.lo ^= b.lo;
    return this;
  }

  irotl(bits) {
    let ahi = this.hi;
    let alo = this.lo;
    let bhi = this.hi;
    let blo = this.lo;

    // a = x << b
    if (bits < 32) {
      ahi <<= bits;
      ahi |= alo >>> (32 - bits);
      alo <<= bits;
    } else {
      ahi = alo << (bits - 32);
      alo = 0;
    }

    bits = 64 - bits;

    // b = x >> (64 - b)
    if (bits < 32) {
      blo >>>= bits;
      blo |= bhi << (32 - bits);
      bhi >>>= bits;
    } else {
      blo = bhi >>> (bits - 32);
      bhi = 0;
    }

    // a | b
    this.hi = ahi | bhi;
    this.lo = alo | blo;

    return this;
  }

  static fromRaw(data, off) {
    const lo = data.readUInt32LE(off);
    const hi = data.readUInt32LE(off + 4);
    return new U64(hi, lo);
  }
}

/*
 * Helpers
 */

function sipround(v0, v1, v2, v3) {
  v0.iadd(v1);
  v1.irotl(13);
  v1.ixor(v0);

  v0.irotl(32);

  v2.iadd(v3);
  v3.irotl(16);
  v3.ixor(v2);

  v0.iadd(v3);
  v3.irotl(21);
  v3.ixor(v0);

  v2.iadd(v1);
  v1.irotl(17);
  v1.ixor(v2);

  v2.irotl(32);
}

// Compute `((uint128_t)a * b) >> 64`
function reduce64(ahi, alo, bhi, blo) {
  const axbhi = mul64(ahi, bhi);
  const axbmid = mul64(ahi, blo);
  const bxamid = mul64(bhi, alo);
  const axblo = mul64(alo, blo);

  // Hack:
  const c = (axbmid.lo >>> 0) + (bxamid.lo >>> 0) + (axblo.hi >>> 0);
  const m = (axbmid.hi >>> 0) + (bxamid.hi >>> 0) + ((c * HI) >>> 0);

  // More hacks:
  const mhi = (m * HI) | 0;
  const mlo = m | 0;

  const {hi, lo} = sum64(axbhi.hi, axbhi.lo, mhi, mlo);

  return [hi, lo];
}

function sum64(ahi, alo, bhi, blo) {
  // Credit to @indutny for this method.
  const lo = (alo + blo) | 0;

  const s = lo >> 31;
  const as = alo >> 31;
  const bs = blo >> 31;

  const c = ((as & bs) | (~s & (as ^ bs))) & 1;

  const hi = (((ahi + bhi) | 0) + c) | 0;

  return { hi, lo };
}

function mul64(alo, blo) {
  const a16 = alo >>> 16;
  const a00 = alo & 0xffff;

  const b16 = blo >>> 16;
  const b00 = blo & 0xffff;

  let c48 = 0;
  let c32 = 0;
  let c16 = 0;
  let c00 = 0;

  c00 += a00 * b00;
  c16 += c00 >>> 16;
  c00 &= 0xffff;
  c16 += a16 * b00;
  c32 += c16 >>> 16;
  c16 &= 0xffff;
  c16 += a00 * b16;
  c32 += c16 >>> 16;
  c16 &= 0xffff;
  c48 += c32 >>> 16;
  c32 &= 0xffff;
  c32 += a16 * b16;
  c48 += c32 >>> 16;
  c32 &= 0xffff;
  c48 += c32 >>> 16;
  c48 &= 0xffff;

  const hi = (c48 << 16) | c32;
  const lo = (c16 << 16) | c00;

  return { hi, lo };
}

/*
 * Expose
 */

exports.siphash = siphash;
exports.siphash256 = siphash; // compat
exports.siphash32 = siphash32;
exports.siphash64 = siphash64;
exports.siphash32k256 = siphash32k256;
exports.siphash64k256 = siphash64k256;
exports.sipmod = sipmod;
