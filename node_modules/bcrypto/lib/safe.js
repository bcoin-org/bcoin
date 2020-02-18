/*!
 * safe.js - constant-time equals for bcrypto
 * Copyright (c) 2016-2018, Christopher Jeffrey (MIT License).
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

const assert = require('bsert');

/*
 * Safe
 */

function safeCompare(x, y) {
  assert(Buffer.isBuffer(x));
  assert(Buffer.isBuffer(y));

  if (safeEqualInt(y.length, 0))
    return safeEqualInt(x.length, 0);

  let v = x.length ^ y.length;

  for (let i = 0; i < x.length; i++)
    v |= x[i] ^ y[i % y.length];

  return safeEqualByte(v, 0);
}

function safeEqual(x, y) {
  assert(Buffer.isBuffer(x));
  assert(Buffer.isBuffer(y));

  // Assumes the lengths of both
  // `x` and `y` are not secret.
  if (x.length !== y.length)
    return 0;

  let v = 0;

  for (let i = 0; i < x.length; i++)
    v |= x[i] ^ y[i];

  return safeEqualByte(v, 0);
}

function safeEqualByte(x, y) {
  return safeEqualInt(x & 0xff, y & 0xff);
}

function safeEqualInt(x, y) {
  return ((x ^ y) - 1) >>> 31;
}

function safeSelect(v, x, y) {
  return (~(v - 1) & x) | ((v - 1) & y);
}

function safeLTE(x, y) {
  return ((x - y - 1) >>> 31) & 1;
}

function safeCopy(v, x, y) {
  assert(Number.isSafeInteger(v));
  assert(Buffer.isBuffer(x));
  assert(Buffer.isBuffer(y));
  assert(x.length === y.length);

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
exports.safeLTE = safeLTE;
exports.safeCopy = safeCopy;
