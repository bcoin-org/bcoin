/*!
 * bcrypt.js - bcrypt for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on joyent/node-bcrypt-pbkdf:
 *   Copyright (c) 2016, Joyent Inc
 *   https://github.com/joyent/node-bcrypt-pbkdf
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/Bcrypt
 *   http://www.usenix.org/events/usenix99/provos/provos_html/node1.html
 *   https://hackernoon.com/the-bcrypt-protocol-is-kind-of-a-mess-4aace5eb31bd
 *   https://github.com/openbsd/src/blob/master/lib/libc/crypt/bcrypt.c
 *   https://github.com/openssh/openssh-portable
 *   https://github.com/openssh/openssh-portable/blob/master/openbsd-compat/bcrypt_pbkdf.c
 *   https://github.com/openssh/openssh-portable/blob/master/openbsd-compat/blowfish.c
 *   https://github.com/joyent/node-bcrypt-pbkdf/blob/master/index.js
 */

'use strict';

const assert = require('../internal/assert');
const SHA512 = require('../sha512');
const Blowfish = require('./ciphers/blowfish');

/*
 * Constants
 */

const CIPHERTEXT192 = Buffer.from('OrpheanBeholderScryDoubt', 'binary');
const BCRYPT_BLOCKS192 = 6;
const BCRYPT_SIZE192 = 24;
const BCRYPT_SALT192 = 16;
const BCRYPT_HASH192 = 23;

const CIPHERTEXT256 = Buffer.from('OxychromaticBlowfishSwatDynamite', 'binary');
const BCRYPT_BLOCKS256 = 8;
const BCRYPT_SIZE256 = 32;

const NUL = Buffer.alloc(1, 0x00);

/*
 * Bcrypt
 */

function hash192(pass, salt, rounds) {
  if (typeof pass === 'string')
    pass = Buffer.from(pass, 'utf8');

  if (typeof salt === 'string')
    salt = Buffer.from(salt, 'utf8');

  if (salt == null)
    salt = Buffer.alloc(0);

  assert(Buffer.isBuffer(pass));
  assert(Buffer.isBuffer(salt));
  assert((rounds >>> 0) === rounds);

  if (rounds < 4 || rounds > 31)
    throw new RangeError('Invalid rounds.');

  return _hash192(Buffer.alloc(BCRYPT_SIZE192), pass, salt, rounds);
}

function derive(pass, salt, rounds, minor = 'b') {
  if (typeof pass === 'string')
    pass = Buffer.from(pass, 'utf8');

  if (typeof salt === 'string')
    salt = Buffer.from(salt, 'utf8');

  assert(Buffer.isBuffer(pass));
  assert(Buffer.isBuffer(salt));
  assert((rounds >>> 0) === rounds);
  assert(typeof minor === 'string');

  if (salt.length !== BCRYPT_SALT192)
    throw new RangeError('Invalid salt length.');

  switch (minor) {
    case 'a':
      pass = Buffer.concat([pass, NUL]);
      pass = pass.slice(0, pass.length & 0xff);
      break;
    case 'b':
      if (pass.length > 72)
        pass = pass.slice(0, 73);
      else
        pass = Buffer.concat([pass, NUL]);
      break;
    default:
      throw new Error('Invalid minor version.');
  }

  return hash192(pass, salt, rounds).slice(0, BCRYPT_HASH192);
}

function generate(pass, salt, rounds, minor = 'b') {
  if (typeof salt === 'string') {
    const [i, data] = decode64(salt, 0, BCRYPT_SALT192);

    if (i !== salt.length || data == null)
      throw new Error('Invalid salt string.');

    salt = data;
  }

  const hash = derive(pass, salt, rounds, minor);

  return encode(minor, rounds, salt, hash);
}

function verify(pass, record) {
  const [minor, rounds, salt, expect] = decode(record);
  const hash = derive(pass, salt, rounds, minor);

  let res = 0;

  for (let i = 0; i < BCRYPT_HASH192; i++)
    res |= hash[i] ^ expect[i];

  return ((res - 1) >>> 31) !== 0;
}

/*
 * PBKDF
 */

function hash256(pass, salt, rounds) {
  if (typeof pass === 'string')
    pass = Buffer.from(pass, 'utf8');

  if (typeof salt === 'string')
    salt = Buffer.from(salt, 'utf8');

  if (salt == null)
    salt = Buffer.alloc(0);

  assert(Buffer.isBuffer(pass));
  assert(Buffer.isBuffer(salt));
  assert((rounds >>> 0) === rounds);

  if (rounds < 4 || rounds > 31)
    throw new RangeError('Invalid rounds.');

  return _hash256(Buffer.alloc(BCRYPT_SIZE256), pass, salt, rounds);
}

function pbkdf(pass, salt, rounds, size) {
  if (typeof pass === 'string')
    pass = Buffer.from(pass, 'utf8');

  if (typeof salt === 'string')
    salt = Buffer.from(salt, 'utf8');

  if (salt == null)
    salt = Buffer.alloc(0);

  assert(Buffer.isBuffer(pass));
  assert(Buffer.isBuffer(salt));
  assert((rounds >>> 0) === rounds);
  assert((size >>> 0) === size);

  const out = Buffer.alloc(BCRYPT_SIZE256);
  const tmpout = Buffer.alloc(BCRYPT_SIZE256);
  const countsalt = Buffer.alloc(salt.length + 4);
  const key = Buffer.alloc(size);

  if (rounds < 1
      || pass.length === 0
      || salt.length === 0
      || size === 0
      || size > out.length ** 2
      || salt.length > (1 << 20)) {
    throw new Error('Invalid bcrypt parameters.');
  }

  const stride = ((size + out.length - 1) / out.length) >>> 0;
  const amount = ((size + stride - 1) / stride) >>> 0;

  salt.copy(countsalt, 0);

  const sha2pass = SHA512.digest(pass);

  let sha2salt = Buffer.alloc(0);
  let keylen = size;
  let amt = amount;

  for (let count = 1; keylen > 0; count++) {
    countsalt[salt.length + 0] = count >>> 24;
    countsalt[salt.length + 1] = count >>> 16;
    countsalt[salt.length + 2] = count >>> 8;
    countsalt[salt.length + 3] = count;

    sha2salt = SHA512.digest(countsalt);

    _hash256(tmpout, sha2pass, sha2salt, 6);

    tmpout.copy(out, 0);

    for (let i = 1; i < rounds; i++) {
      sha2salt = SHA512.digest(tmpout);

      _hash256(tmpout, sha2pass, sha2salt, 6);

      for (let j = 0; j < out.length; j++)
        out[j] ^= tmpout[j];
    }

    amt = Math.min(amt, keylen);

    let i = 0;

    for (; i < amt; i++) {
      const dest = i * stride + (count - 1);

      if (dest >= size)
        break;

      key[dest] = out[i];
    }

    keylen -= i;
  }

  return key;
}

async function pbkdfAsync(pass, salt, rounds, size) {
  return pbkdf(pass, salt, rounds, size);
}

/*
 * Hashing
 */

function _hash192(out, pass, salt, rounds) {
  const state = new Blowfish();
  const cdata = new Uint32Array(BCRYPT_BLOCKS192);

  state.init(pass, salt);

  const r = 2 ** rounds;

  for (let i = 0; i < r; i++) {
    state.expand0state(pass);
    state.expand0state(salt);
  }

  for (let i = 0; i < BCRYPT_BLOCKS192; i++)
    cdata[i] = state.stream2word(CIPHERTEXT192);

  for (let i = 0; i < 64; i++)
    state.enc(cdata);

  for (let i = 0; i < BCRYPT_BLOCKS192; i++) {
    out[4 * i + 0] = cdata[i] >>> 24;
    out[4 * i + 1] = cdata[i] >>> 16;
    out[4 * i + 2] = cdata[i] >>> 8;
    out[4 * i + 3] = cdata[i];
  }

  return out;
}

function _hash256(out, pass, salt, rounds) {
  const state = new Blowfish();
  const cdata = new Uint32Array(BCRYPT_BLOCKS256);

  state.init(pass, salt);

  const r = 2 ** rounds;

  for (let i = 0; i < r; i++) {
    state.expand0state(salt);
    state.expand0state(pass);
  }

  for (let i = 0; i < BCRYPT_BLOCKS256; i++)
    cdata[i] = state.stream2word(CIPHERTEXT256);

  for (let i = 0; i < 64; i++)
    state.enc(cdata);

  for (let i = 0; i < BCRYPT_BLOCKS256; i++) {
    out[4 * i + 3] = cdata[i] >>> 24;
    out[4 * i + 2] = cdata[i] >>> 16;
    out[4 * i + 1] = cdata[i] >>> 8;
    out[4 * i + 0] = cdata[i];
  }

  return out;
}

/*
 * Encoding
 */

function encode(minor, rounds, salt, hash) {
  assert(typeof minor === 'string');
  assert((rounds >>> 0) === rounds);
  assert(Buffer.isBuffer(salt));
  assert(Buffer.isBuffer(hash));
  assert(minor === 'a' || minor === 'b');
  assert(rounds >= 4 && rounds <= 31);
  assert(salt.length === BCRYPT_SALT192);
  assert(hash.length === BCRYPT_HASH192);

  let logr = rounds.toString(10);

  if (rounds < 10)
    logr = '0' + logr;

  return `$2${minor}$${logr}$${encode64(salt)}${encode64(hash)}`;
}

function decode(str) {
  assert(typeof str === 'string');

  if (str.length < 46)
    throw new Error('Invalid bcrypt string.');

  if (str[0] !== '$' || str[1] !== '2')
    throw new Error('Invalid major version.');

  const minor = str[2];

  switch (minor) {
    case 'a':
    case 'b':
      break;
    default:
      throw new Error('Invalid minor version.');
  }

  if (str[3] !== '$')
    throw new Error('Invalid bcrypt string.');

  const p = str.charCodeAt(4) - 0x30;
  const q = str.charCodeAt(5) - 0x30;

  if (p < 0 || p > 9 || q < 0 || q > 9)
    throw new Error('Invalid bcrypt string.');

  const rounds = p * 10 + q;

  if (rounds < 4 || rounds > 31)
    throw new Error('Invalid log rounds.');

  if (str[6] !== '$')
    throw new Error('Invalid bcrypt string.');

  let i = 7;
  let salt, hash;

  [i, salt] = decode64(str, i, BCRYPT_SALT192);

  if (salt == null)
    throw new Error('Invalid salt.');

  [i, hash] = decode64(str, i, BCRYPT_HASH192);

  if (hash == null)
    throw new Error('Invalid hash.');

  if (i !== str.length)
    throw new Error('Invalid bcrypt string.');

  return [minor, rounds, salt, hash];
}

/*
 * Base64
 */

const CHARSET =
  './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

const TABLE = [
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,  0,  1,
  54, 55, 56, 57, 58, 59, 60, 61, 62, 63, -1, -1, -1, -1, -1, -1,
  -1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16,
  17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, -1, -1, -1, -1, -1,
  -1, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
  43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, -1, -1, -1, -1, -1
];

function encode64(data) {
  assert(Buffer.isBuffer(data));

  let p = 0;
  let s = '';
  let a, b;

  while (p < data.length) {
    a = data[p++];
    s += CHARSET[(a >>> 2)];
    a = (a & 3) << 4;

    if (p >= data.length) {
      s += CHARSET[a];
      break;
    }

    b = data[p++];
    a |= (b >>> 4) & 15;
    s += CHARSET[a];
    a = (b & 0x0f) << 2;

    if (p >= data.length) {
      s += CHARSET[a];
      break;
    }

    b = data[p++];
    a |= (b >>> 6) & 3;
    s += CHARSET[a];
    s += CHARSET[b & 63];
  }

  return s;
}

function decode64(s, i, len) {
  assert(typeof s === 'string');
  assert((i >>> 0) === i);
  assert((len >>> 0) === len);

  const data = Buffer.alloc(len);

  let p = 0;
  let a, b, c, d;

  while (p < len) {
    a = unbase64(s, i++);

    if (a === -1)
      return [i, null];

    b = unbase64(s, i++);

    if (b === -1)
      return [i, null];

    data[p++] = (a << 2) | ((b & 48) >>> 4);

    if (p >= len)
      break;

    c = unbase64(s, i++);

    if (c === -1)
      return [i, null];

    data[p++] = ((b & 15) << 4) | ((c & 60) >>> 2);

    if (p >= len)
      break;

    d = unbase64(s, i++);

    if (d === -1)
      return [i, null];

    data[p++] = ((c & 3) << 6) | d;
  }

  return [i, data];
}

function unbase64(s, i) {
  if (i >= s.length)
    return -1;

  const ch = s.charCodeAt(i);

  if (ch & 0xff80)
    return -1;

  return TABLE[ch];
}

/*
 * Expose
 */

exports.native = 0;
exports.hash192 = hash192;
exports.derive = derive;
exports.generate = generate;
exports.verify = verify;
exports.hash256 = hash256;
exports.pbkdf = pbkdf;
exports.pbkdfAsync = pbkdfAsync;
