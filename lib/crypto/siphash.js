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

var native = require('../utils/native').binding;

/**
 * Javascript siphash implementation. Used for compact block relay.
 * @alias module:crypto/siphash.siphash24
 * @param {Buffer} data
 * @param {Buffer} key - 128 bit key.
 * @returns {Buffer} uint64le
 */

function siphash24(data, key, shift) {
  var blocks = Math.floor(data.length / 8);
  var c0 = U64(0x736f6d65, 0x70736575);
  var c1 = U64(0x646f7261, 0x6e646f6d);
  var c2 = U64(0x6c796765, 0x6e657261);
  var c3 = U64(0x74656462, 0x79746573);
  var f0 = U64(blocks << (shift - 32), 0);
  var f1 = U64(0, 0xff);
  var k0 = U64.fromRaw(key, 0);
  var k1 = U64.fromRaw(key, 8);
  var p = 0;
  var i, d, v0, v1, v2, v3;

  // Init
  v0 = c0.ixor(k0);
  v1 = c1.ixor(k1);
  v2 = c2.ixor(k0);
  v3 = c3.ixor(k1);

  // Blocks
  for (i = 0; i < blocks; i++) {
    d = U64.fromRaw(data, p);
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

  return v0.toRaw();
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
 * Javascript siphash implementation. Used for compact block relay.
 * @alias module:crypto/siphash.siphash
 * @param {Buffer} data
 * @param {Buffer} key - 128 bit key.
 * @returns {Buffer} uint64le
 */

function siphash(data, key) {
  return siphash24(data, key, 56);
}

/**
 * Javascript siphash implementation. Used for compact block relay.
 * @alias module:crypto/siphash.siphash256
 * @param {Buffer} data
 * @param {Buffer} key - 128 bit key.
 * @returns {Buffer} uint64le
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
  var a = this;
  var sum, c;

  // Credit to @indutny for this method.
  sum = (a.lo >>> 0) + (b.lo >>> 0);
  c = (sum >= 0x100000000) | 0;

  a.hi = (((a.hi + b.hi) | 0) + c) | 0;
  a.lo = sum | 0;

  return a;
};

U64.prototype.ixor = function ixor(b) {
  this.hi ^= b.hi;
  this.lo ^= b.lo;
  return this;
};

U64.prototype.irotl = function irotl(bits) {
  var ahi = this.hi;
  var alo = this.lo;
  var bhi = this.hi;
  var blo = this.lo;

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

U64.prototype.toRaw = function toRaw() {
  var data = Buffer.allocUnsafe(8);
  data.writeUInt32LE(this.hi >>> 0, 4, true);
  data.writeUInt32LE(this.lo >>> 0, 0, true);
  return data;
};

U64.fromRaw = function fromRaw(data, off) {
  var hi, lo;

  if (!off)
    off = 0;

  hi = data.readUInt32LE(off + 4, true);
  lo = data.readUInt32LE(off, true);

  return new U64(hi, lo);
};

/*
 * Expose
 */

exports = siphash256;
exports.siphash = siphash;
exports.siphash256 = siphash256;
exports.U64 = U64;

module.exports = exports;
