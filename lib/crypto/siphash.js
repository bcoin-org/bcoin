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
  v0 = c0.xor(k0);
  v1 = c1.xor(k1);
  v2 = c2.xor(k0);
  v3 = c3.xor(k1);

  // Blocks
  for (i = 0; i < blocks; i++) {
    d = U64.fromRaw(data, p);
    p += 8;
    v3.xor(d);
    sipround(v0, v1, v2, v3);
    sipround(v0, v1, v2, v3);
    v0.xor(d);
  }

  switch (data.length & 7) {
    case 7:
      f0.hi |= data[p + 6] << 16;
    case 6:
      f0.hi |= data[p + 5] << 8;
    case 5:
      f0.hi |= data[p + 4] << 0;
    case 4:
      f0.lo |= data[p + 3] << 24;
    case 3:
      f0.lo |= data[p + 2] << 16;
    case 2:
      f0.lo |= data[p + 1] << 8;
    case 1:
      f0.lo |= data[p + 0] << 0;
      if (f0.lo < 0)
        f0.lo += 0x100000000;
      if (f0.hi < 0)
        f0.hi += 0x100000000;
      break;
    case 0:
      break;
  }

  // Finalization
  v3.xor(f0);
  sipround(v0, v1, v2, v3);
  sipround(v0, v1, v2, v3);
  v0.xor(f0);
  v2.xor(f1);
  sipround(v0, v1, v2, v3);
  sipround(v0, v1, v2, v3);
  sipround(v0, v1, v2, v3);
  sipround(v0, v1, v2, v3);
  v0.xor(v1);
  v0.xor(v2);
  v0.xor(v3);

  return v0.toRaw();
}

function sipround(v0, v1, v2, v3) {
  v0.add(v1);
  v1.rotl(13);
  v1.xor(v0);

  v0.rotl(32);

  v2.add(v3);
  v3.rotl(16);
  v3.xor(v2);

  v0.add(v3);
  v3.rotl(21);
  v3.xor(v0);

  v2.add(v1);
  v1.rotl(17);
  v1.xor(v2);

  v2.rotl(32);
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

  this.hi = 0;
  this.lo = 0;
  this.join(hi, lo);
}

U64.prototype.join = function join(hi, lo) {
  this.hi = hi >>> 0;
  this.lo = lo >>> 0;
  return this;
};

U64.prototype.add = function add(b) {
  var a = this;
  var a48 = a.hi >>> 16;
  var a32 = a.hi & 0xffff;
  var a16 = a.lo >>> 16;
  var a00 = a.lo & 0xffff;
  var b48 = b.hi >>> 16;
  var b32 = b.hi & 0xffff;
  var b16 = b.lo >>> 16;
  var b00 = b.lo & 0xffff;
  var c48 = 0;
  var c32 = 0;
  var c16 = 0;
  var c00 = 0;
  var hi, lo;

  c00 += a00 + b00;
  c16 += c00 >>> 16;
  c00 &= 0xffff;
  c16 += a16 + b16;
  c32 += c16 >>> 16;
  c16 &= 0xffff;
  c32 += a32 + b32;
  c48 += c32 >>> 16;
  c32 &= 0xffff;
  c48 += a48 + b48;
  c48 &= 0xffff;

  hi = (c48 << 16) | c32;
  lo = (c16 << 16) | c00;

  return a.join(hi, lo);
};

U64.prototype.xor = function xor(b) {
  return this.join(this.hi ^ b.hi, this.lo ^ b.lo);
};

U64.prototype.rotl = function rotl(bits) {
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
  return this.join(ahi | bhi, alo | blo);
};

U64.prototype.toRaw = function toRaw() {
  var data = Buffer.allocUnsafe(8);
  data.writeUInt32LE(this.hi, 4, true);
  data.writeUInt32LE(this.lo, 0, true);
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
