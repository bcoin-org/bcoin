/*!
 * siphash.js - siphash for bcoin
 * Copyright (c) 2016-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 *
 * Ported from:
 * https://github.com/bitcoin/bitcoin/blob/master/src/hash.cpp
 */

'use strict';

/**
 * @module crypto/siphash
 */

const native = require('../native').binding;

/**
 * Javascript siphash implementation. Used for compact block relay.
 * @alias module:crypto/siphash.siphash24
 * @param {Buffer} data
 * @param {Buffer} key - 128 bit key.
 * @returns {Array} [hi, lo]
 */

function siphash24(data, key, shift) {
  const blocks = Math.floor(data.length / 8);
  const c0 = U64(0x736f6d65, 0x70736575);
  const c1 = U64(0x646f7261, 0x6e646f6d);
  const c2 = U64(0x6c796765, 0x6e657261);
  const c3 = U64(0x74656462, 0x79746573);
  const f0 = U64(blocks << (shift - 32), 0);
  const f1 = U64(0, 0xff);
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

/**
 * Javascript siphash implementation (shift=56).
 * @alias module:crypto/siphash.siphash
 * @param {Buffer} data
 * @param {Buffer} key - 128 bit key.
 * @returns {Array} [hi, lo]
 */

function siphash(data, key) {
  return siphash24(data, key, 56);
}

/**
 * Javascript siphash implementation (shift=59).
 * @alias module:crypto/siphash.siphash256
 * @param {Buffer} data
 * @param {Buffer} key - 128 bit key.
 * @returns {Array} [hi, lo]
 */

function siphash256(data, key) {
  return siphash24(data, key, 59);
}

if (native) {
  siphash = native.siphash;
  siphash256 = native.siphash256;
}

/*
 * U64
 * @constructor
 * @ignore
 */

function U64(hi, lo) {
  if (!(this instanceof U64))
    return new U64(hi, lo);

  this.hi = hi | 0;
  this.lo = lo | 0;
}

U64.prototype.iadd = function iadd(b) {
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
};

U64.prototype.ixor = function ixor(b) {
  this.hi ^= b.hi;
  this.lo ^= b.lo;
  return this;
};

U64.prototype.irotl = function irotl(bits) {
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
};

U64.fromRaw = function fromRaw(data, off) {
  const lo = data.readUInt32LE(off, true);
  const hi = data.readUInt32LE(off + 4, true);
  return new U64(hi, lo);
};

/*
 * Expose
 */

exports = siphash;
exports.siphash = siphash;
exports.siphash256 = siphash256;

module.exports = exports;
