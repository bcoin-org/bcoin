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
 * Helpers
 */

function U64(hi, lo) {
  if (!(this instanceof U64))
    return new U64(hi, lo);

  this.hi = hi || 0;
  this.lo = lo || 0;
}

U64.prototype.add = function add(b) {
  var r, carry;

  r = this.lo + b.lo;
  carry = (r - (r % 0x100000000)) / 0x100000000;
  this.hi = (this.hi + b.hi + carry) & 0xffffffff;
  this.lo = r & 0xffffffff;

  if (this.hi < 0)
    this.hi += 0x100000000;

  if (this.lo < 0)
    this.lo += 0x100000000;

  return this;
};

U64.prototype.xor = function xor(b) {
  this.hi ^= b.hi;
  this.lo ^= b.lo;

  if (this.hi < 0)
    this.hi += 0x100000000;

  if (this.lo < 0)
    this.lo += 0x100000000;

  return this;
};

U64.prototype.rotl = function rotl(b) {
  var h1, l1, h2, l2, c;

  // v1 = x << b
  if (b < 32) {
    h1 = this.hi << b;
    c = this.lo >>> (32 - b);
    l1 = this.lo << b;
    h1 |= c;
  } else {
    h1 = this.lo << (b - 32);
    l1 = 0;
  }

  // v2 = x >> (64 - b)
  b = 64 - b;
  if (b < 32) {
    h2 = this.hi >>> b;
    c = this.hi & (0xffffffff >>> (32 - b));
    l2 = this.lo >>> b;
    l2 |= c << (32 - b);
  } else {
    h2 = 0;
    l2 = this.hi >>> (b - 32);
  }

  // v1 | v2
  this.hi = h1 | h2;
  this.lo = l1 | l2;

  if (this.hi < 0)
    this.hi += 0x100000000;

  if (this.lo < 0)
    this.lo += 0x100000000;

  return this;
};

U64.prototype.toRaw = function toRaw() {
  var data = new Buffer(8);
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
