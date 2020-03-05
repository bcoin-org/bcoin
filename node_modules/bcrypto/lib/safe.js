/*!
 * safe.js - constant-time equals for bcrypto
 * Copyright (c) 2016-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on golang/go:
 *   Copyright (c) 2009 The Go Authors. All rights reserved.
 *   https://github.com/golang/go
 *
 * Resources:
 *   https://github.com/golang/go/blob/master/src/crypto/subtle/constant_time.go
 */

'use strict';

const assert = require('./internal/assert');

/*
 * Safe
 */

function safeCompare(x, y) {
  assert(Buffer.isBuffer(x));
  assert(Buffer.isBuffer(y));

  if (safeEqualInt(x.length, 0))
    return safeEqualInt(y.length, 0);

  // Assumes `y` is the "constant size"
  // parameter. Note that constant size
  // doesn't necessarily mean secret.
  // Assuming we have a constant-size
  // secret key or passphrase. This
  // function should be called as:
  //
  // if (!safeCompare(input, key))
  //   throw new Error('Bad passphrase.');
  let v = x.length ^ y.length;

  for (let i = 0; i < y.length; i++)
    v |= x[i % x.length] ^ y[i];

  return (v - 1) >>> 31;
}

function safeEqual(x, y) {
  assert(Buffer.isBuffer(x));
  assert(Buffer.isBuffer(y));

  // Assumes the lengths of both
  // `x` and `y` are not secret.
  if (!safeEqualInt(x.length, y.length))
    return 0;

  let v = 0;

  for (let i = 0; i < x.length; i++)
    v |= x[i] ^ y[i];

  return (v - 1) >>> 31;
}

function safeEqualByte(x, y) {
  return safeEqualInt(x & 0xff, y & 0xff);
}

function safeEqualInt(x, y) {
  return ((x ^ y) - 1) >>> 31;
}

function safeSelect(x, y, v) {
  return (x & (v - 1)) | (y & ~(v - 1));
}

function safeLT(x, y) {
  return (x - y) >>> 31;
}

function safeLTE(x, y) {
  return (x - y - 1) >>> 31;
}

function safeGT(x, y) {
  return (y - x) >>> 31;
}

function safeGTE(x, y) {
  return (y - x - 1) >>> 31;
}

function safeMin(x, y) {
  return safeSelect(x, y, safeLT(y, x));
}

function safeMax(x, y) {
  return safeSelect(x, y, safeGT(y, x));
}

function safeAbs(x) {
  return (x | 0) * ((x >> 31) | 1);
}

function safeBool(x) {
  return ((x >> 31) | (-x >> 31)) & 1;
}

function safeCopy(x, y, v) {
  assert(Buffer.isBuffer(x));
  assert(Buffer.isBuffer(y));
  assert(safeEqualInt(x.length, y.length));

  const xmask = (v - 1) & 0xff;
  const ymask = ~(v - 1) & 0xff;

  for (let i = 0; i < x.length; i++)
    x[i] = (x[i] & xmask) | (y[i] & ymask);
}

/*
 * Expose
 */

exports.safeCompare = safeCompare;
exports.safeEqual = safeEqual;
exports.safeEqualByte = safeEqualByte;
exports.safeEqualInt = safeEqualInt;
exports.safeSelect = safeSelect;
exports.safeLT = safeLT;
exports.safeLTE = safeLTE;
exports.safeGT = safeGT;
exports.safeGTE = safeGTE;
exports.safeMin = safeMin;
exports.safeMax = safeMax;
exports.safeAbs = safeAbs;
exports.safeBool = safeBool;
exports.safeCopy = safeCopy;
