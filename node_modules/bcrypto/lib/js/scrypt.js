/*!
 * scrypt.js - scrypt for bcrypto
 * Copyright (c) 2016-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on Tarsnap/scrypt:
 *   Copyright (c) 2005-2016, Colin Percival. All rights reserved.
 *   Copyright (c) 2005-2016, Tarsnap Backup Inc. All rights reserved.
 *   Copyright (c) 2014, Sean Kelly. All rights reserved.
 *   https://github.com/Tarsnap/scrypt
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/Scrypt
 *   http://www.tarsnap.com/scrypt.html
 *   http://www.tarsnap.com/scrypt/scrypt.pdf
 *   https://github.com/Tarsnap/scrypt/blob/master/lib/crypto/crypto_scrypt-ref.c
 */

/* eslint camelcase: "off" */

'use strict';

const assert = require('../internal/assert');
const pbkdf2 = require('../pbkdf2');
const SHA256 = require('../sha256');

/*
 * Constants
 */

const SLAB1 = Buffer.alloc(64);
const SLAB2 = new Uint32Array(16);
const SLAB3 = new Uint32Array(16);

/**
 * Perform scrypt key derivation.
 * @param {Buffer} passwd
 * @param {Buffer} salt
 * @param {Number} N
 * @param {Number} r
 * @param {Number} p
 * @param {Number} len
 * @returns {Buffer}
 */

function derive(passwd, salt, N, r, p, len) {
  if (typeof passwd === 'string')
    passwd = Buffer.from(passwd, 'utf8');

  if (typeof salt === 'string')
    salt = Buffer.from(salt, 'utf8');

  if (salt == null)
    salt = Buffer.alloc(0);

  assert(Buffer.isBuffer(passwd));
  assert(Buffer.isBuffer(salt));
  assert((N >>> 0) === N);
  assert((r >>> 0) === r);
  assert((p >>> 0) === p);
  assert((len >>> 0) === len);

  if (r * p >= (1 << 30))
    throw new Error('EFBIG');

  if ((N & (N - 1)) !== 0 || N === 0)
    throw new Error('EINVAL');

  if (N > 0xffffffff)
    throw new Error('EINVAL');

  const XY = Buffer.alloc(256 * r);
  const V = Buffer.alloc(128 * r * N);
  const B = pbkdf2.derive(SHA256, passwd, salt, 1, p * 128 * r);

  for (let i = 0; i < p; i++)
    smix(B, i * 128 * r, r, N, V, XY);

  clear();

  return pbkdf2.derive(SHA256, passwd, B, 1, len);
}

/**
 * Perform scrypt key derivation (async).
 * @param {Buffer} passwd
 * @param {Buffer} salt
 * @param {Number} N
 * @param {Number} r
 * @param {Number} p
 * @param {Number} len
 * @returns {Promise}
 */

async function deriveAsync(passwd, salt, N, r, p, len) {
  if (typeof passwd === 'string')
    passwd = Buffer.from(passwd, 'utf8');

  if (typeof salt === 'string')
    salt = Buffer.from(salt, 'utf8');

  if (salt == null)
    salt = Buffer.alloc(0);

  assert(Buffer.isBuffer(passwd));
  assert(Buffer.isBuffer(salt));
  assert((N >>> 0) === N);
  assert((r >>> 0) === r);
  assert((p >>> 0) === p);
  assert((len >>> 0) === len);

  if (r * p >= (1 << 30))
    throw new Error('EFBIG');

  if ((N & (N - 1)) !== 0 || N === 0)
    throw new Error('EINVAL');

  if (N > 0xffffffff)
    throw new Error('EINVAL');

  const XY = Buffer.alloc(256 * r);
  const V = Buffer.alloc(128 * r * N);
  const B = await pbkdf2.deriveAsync(SHA256, passwd, salt, 1, p * 128 * r);

  for (let i = 0; i < p; i++)
    await smixAsync(B, i * 128 * r, r, N, V, XY);

  clear();

  return pbkdf2.deriveAsync(SHA256, passwd, B, 1, len);
}

/*
 * Helpers
 */

function salsa20_8(B) {
  const B32 = SLAB2;
  const X = SLAB3;

  for (let i = 0; i < 16; i++)
    B32[i] = readU32(B, i * 4);

  for (let i = 0; i < 16; i++)
    X[i] = B32[i];

  for (let i = 0; i < 8; i += 2) {
    X[4] ^= R(X[0] + X[12], 7);
    X[8] ^= R(X[4] + X[0], 9);
    X[12] ^= R(X[8] + X[4], 13);
    X[0] ^= R(X[12] + X[8], 18);

    X[9] ^= R(X[5] + X[1], 7);
    X[13] ^= R(X[9] + X[5], 9);
    X[1] ^= R(X[13] + X[9], 13);
    X[5] ^= R(X[1] + X[13], 18);

    X[14] ^= R(X[10] + X[6], 7);
    X[2] ^= R(X[14] + X[10], 9);
    X[6] ^= R(X[2] + X[14], 13);
    X[10] ^= R(X[6] + X[2], 18);

    X[3] ^= R(X[15] + X[11], 7);
    X[7] ^= R(X[3] + X[15], 9);
    X[11] ^= R(X[7] + X[3], 13);
    X[15] ^= R(X[11] + X[7], 18);

    X[1] ^= R(X[0] + X[3], 7);
    X[2] ^= R(X[1] + X[0], 9);
    X[3] ^= R(X[2] + X[1], 13);
    X[0] ^= R(X[3] + X[2], 18);

    X[6] ^= R(X[5] + X[4], 7);
    X[7] ^= R(X[6] + X[5], 9);
    X[4] ^= R(X[7] + X[6], 13);
    X[5] ^= R(X[4] + X[7], 18);

    X[11] ^= R(X[10] + X[9], 7);
    X[8] ^= R(X[11] + X[10], 9);
    X[9] ^= R(X[8] + X[11], 13);
    X[10] ^= R(X[9] + X[8], 18);

    X[12] ^= R(X[15] + X[14], 7);
    X[13] ^= R(X[12] + X[15], 9);
    X[14] ^= R(X[13] + X[12], 13);
    X[15] ^= R(X[14] + X[13], 18);
  }

  for (let i = 0; i < 16; i++)
    B32[i] += X[i];

  for (let i = 0; i < 16; i++)
    writeU32(B, B32[i], 4 * i);
}

function R(a, b) {
  return (a << b) | (a >>> (32 - b));
}

function blockmix_salsa8(B, Y, Yo, r) {
  const X = SLAB1;

  blkcpy(X, B, 0, (2 * r - 1) * 64, 64);

  for (let i = 0; i < 2 * r; i++) {
    blkxor(X, B, 0, i * 64, 64);
    salsa20_8(X);
    blkcpy(Y, X, Yo + i * 64, 0, 64);
  }

  for (let i = 0; i < r; i++)
    blkcpy(B, Y, i * 64, Yo + (i * 2) * 64, 64);

  for (let i = 0; i < r; i++)
    blkcpy(B, Y, (i + r) * 64, Yo + (i * 2 + 1) * 64, 64);
}

function integerify(B, r) {
  return readU32(B, (2 * r - 1) * 64);
}

function smix(B, Bo, r, N, V, XY) {
  const X = XY;
  const Y = XY;

  blkcpy(X, B, 0, Bo, 128 * r);

  for (let i = 0; i < N; i++) {
    blkcpy(V, X, i * (128 * r), 0, 128 * r);
    blockmix_salsa8(X, Y, 128 * r, r);
  }

  for (let i = 0; i < N; i++) {
    const j = integerify(X, r) & (N - 1);

    blkxor(X, V, 0, j * (128 * r), 128 * r);
    blockmix_salsa8(X, Y, 128 * r, r);
  }

  blkcpy(B, X, Bo, 0, 128 * r);
}

async function smixAsync(B, Bo, r, N, V, XY) {
  const X = XY;
  const Y = XY;

  blkcpy(X, B, 0, Bo, 128 * r);

  for (let i = 0; i < N; i++) {
    blkcpy(V, X, i * (128 * r), 0, 128 * r);
    blockmix_salsa8(X, Y, 128 * r, r);

    await wait();
  }

  for (let i = 0; i < N; i++) {
    const j = integerify(X, r) & (N - 1);

    blkxor(X, V, 0, j * (128 * r), 128 * r);
    blockmix_salsa8(X, Y, 128 * r, r);

    await wait();
  }

  blkcpy(B, X, Bo, 0, 128 * r);
}

function blkcpy(dst, src, dstOff, srcOff, len) {
  src.copy(dst, dstOff, srcOff, srcOff + len);
}

function blkxor(dst, src, dstOff, srcOff, len) {
  for (let i = 0; i < len; i++)
    dst[dstOff + i] ^= src[srcOff + i];
}

function wait() {
  return new Promise(r => setImmediate(r));
}

function clear() {
  for (let i = 0; i < 64; i++)
    SLAB1[i] = 0;

  for (let i = 0; i < 16; i++) {
    SLAB2[i] = 0;
    SLAB3[i] = 0;
  }
}

function readU32(data, off) {
  return (data[off++]
        + data[off++] * 0x100
        + data[off++] * 0x10000
        + data[off] * 0x1000000);
}

function writeU32(dst, num, off) {
  dst[off++] = num;
  num >>>= 8;
  dst[off++] = num;
  num >>>= 8;
  dst[off++] = num;
  num >>>= 8;
  dst[off++] = num;
  return off;
}

/*
 * Expose
 */

exports.native = 0;
exports.derive = derive;
exports.deriveAsync = deriveAsync;
