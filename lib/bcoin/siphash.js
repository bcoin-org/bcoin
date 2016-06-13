/*!
 * siphash.js - siphash for bcoin
 * Copyright (c) 2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 *
 * Ported from:
 * https://github.com/bitcoin/bitcoin/blob/master/src/hash.cpp
 */

'use strict';

/**
 * Javascript siphash implementation. Used for compact block relay.
 * @param {Buffer} data - Blocks are uint64le's.
 * @param {Buffer} k0 - Must be encoded as a uint64le.
 * @param {Buffer} k1 - Must be encoded as a uint64le.
 * @returns {Buffer} uint64le
 */

function siphash(data, k0, k1) {
  var out = new Buffer(8);
  var blocks = Math.ceil(data.length / 8);
  var c0 = { hi: 0x736f6d65, lo: 0x70736575 };
  var c1 = { hi: 0x646f7261, lo: 0x6e646f6d };
  var c2 = { hi: 0x6c796765, lo: 0x6e657261 };
  var c3 = { hi: 0x74656462, lo: 0x79746573 };
  var f0 = { hi: blocks << 27, lo: 0 };
  var f1 = { hi: 0, lo: 0xff };
  var i, d, v0, v1, v2, v3;

  k0 = read(k0, 0);
  k1 = read(k1, 0);

  // Init
  v0 = xor64(c0, k0);
  v1 = xor64(c1, k1);
  v2 = xor64(c2, k0);
  v3 = xor64(c3, k1);

  // Blocks
  for (i = 0; i < blocks; i++) {
    d = read(data, i * 8);
    xor64(v3, d);
    sipround(v0, v1, v2, v3);
    sipround(v0, v1, v2, v3);
    xor64(v0, d);
  }

  // Finalization
  xor64(v3, f0);
  sipround(v0, v1, v2, v3);
  sipround(v0, v1, v2, v3);
  xor64(v0, f0);
  xor64(v2, f1);
  sipround(v0, v1, v2, v3);
  sipround(v0, v1, v2, v3);
  sipround(v0, v1, v2, v3);
  sipround(v0, v1, v2, v3);
  xor64(v0, v1);
  xor64(v0, v2);
  xor64(v0, v3);

  write(out, v0, 0);

  return out;
}

function sipround(v0, v1, v2, v3) {
  sum64(v0, v1);
  rotl64(v1, 13);
  xor64(v1, v0);

  rotl64(v0, 32);

  sum64(v2, v3);
  rotl64(v3, 16);
  xor64(v3, v2);

  sum64(v0, v3);
  rotl64(v3, 21);
  xor64(v3, v0);

  sum64(v2, v1);
  rotl64(v1, 17);
  xor64(v1, v2);

  rotl64(v2, 32);
}

/*
 * Helpers
 */

function sum64(a, b) {
  var r, carry;

  r = a.lo + b.lo;
  carry = (r - (r % 0x100000000)) / 0x100000000;
  a.hi = (a.hi + b.hi + carry) & 0xffffffff;
  a.lo = r & 0xffffffff;

  if (a.hi < 0)
    a.hi += 0x100000000;

  if (a.lo < 0)
    a.lo += 0x100000000;

  return a;
}

function rotl64(x, b) {
  var h1, l1, h2, l2, c;

  // v1 = x << b
  if (b < 32) {
    h1 = x.hi << b;
    c = x.lo >>> (32 - b);
    l1 = x.lo << b;
    h1 |= c;
  } else {
    h1 = x.lo << (b - 32);
    l1 = 0;
  }

  // v2 = x >> (64 - b)
  b = 64 - b;
  if (b < 32) {
    h2 = x.hi >>> b;
    c = x.hi & (0xffffffff >>> (32 - b));
    l2 = x.lo >>> b;
    l2 |= c << (32 - b);
  } else {
    h2 = 0;
    l2 = x.hi >>> (b - 32);
  }

  // v1 | v2
  x.hi = h1 | h2;
  x.lo = l1 | l2;

  if (x.hi < 0)
    x.hi += 0x100000000;

  if (x.lo < 0)
    x.lo += 0x100000000;

  return x;
}

function xor64(a, b) {
  a.hi ^= b.hi;
  a.lo ^= b.lo;

  if (a.hi < 0)
    a.hi += 0x100000000;

  if (a.lo < 0)
    a.lo += 0x100000000;

  return a;
}

function read(data, off) {
  return {
    hi: data.readUInt32LE(off + 4, true),
    lo: data.readUInt32LE(off, true)
  };
}

function write(data, value, off) {
  data.writeUInt32LE(value.hi, off + 4, true);
  data.writeUInt32LE(value.lo, off, true);
}

/*
 * Expose
 */

exports = siphash;
exports.write = write;
exports.read = read;

module.exports = exports;
