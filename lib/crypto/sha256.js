/*!
 * sha256.js - SHA256 implementation for bcoin
 * Copyright (c) 2016-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 * Parts of this software based on hash.js.
 */

'use strict';

/**
 * @module crypto/sha256
 * @ignore
 */

/*
 * Constants
 */

const DESC = Buffer.allocUnsafe(8);
const BUFFER64 = Buffer.allocUnsafe(64);
const PADDING = Buffer.allocUnsafe(64);

const K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];

PADDING.fill(0);
PADDING[0] = 0x80;

/**
 * SHA256
 * @alias module:crypto/sha256.SHA256
 * @constructor
 * @property {Number[]} s
 * @property {Number[]} w
 * @property {Buffer} block
 * @property {Number} bytes
 */

function SHA256() {
  if (!(this instanceof SHA256))
    return new SHA256();

  this.s = new Array(8);
  this.w = new Array(64);
  this.block = Buffer.allocUnsafe(64);
  this.bytes = 0;
}

/**
 * Initialize SHA256 context.
 */

SHA256.prototype.init = function init() {
  this.s[0] = 0x6a09e667;
  this.s[1] = 0xbb67ae85;
  this.s[2] = 0x3c6ef372;
  this.s[3] = 0xa54ff53a;
  this.s[4] = 0x510e527f;
  this.s[5] = 0x9b05688c;
  this.s[6] = 0x1f83d9ab;
  this.s[7] = 0x5be0cd19;
  this.bytes = 0;
};

/**
 * Update SHA256 context.
 * @param {Buffer} data
 */

SHA256.prototype.update = function update(data) {
  return this._update(data, data.length);
};

/**
 * Finalize SHA256 context.
 * @returns {Buffer}
 */

SHA256.prototype.finish = function finish() {
  return this._finish(Buffer.allocUnsafe(32));
};

/**
 * Update SHA256 context.
 * @private
 * @param {Buffer} data
 * @param {Number} len
 */

SHA256.prototype._update = function update(data, len) {
  let size = this.bytes & 0x3f;
  let pos = 0;

  this.bytes += len;

  if (size > 0) {
    let want = 64 - size;

    if (want > len)
      want = len;

    for (let i = 0; i < want; i++)
      this.block[size + i] = data[i];

    size += want;
    len -= want;
    pos += want;

    if (size < 64)
      return;

    this.transform(this.block, 0);
  }

  while (len >= 64) {
    this.transform(data, pos);
    pos += 64;
    len -= 64;
  }

  for (let i = 0; i < len; i++)
    this.block[i] = data[pos + i];
};

/**
 * Finalize SHA256 context.
 * @private
 * @param {Buffer} out
 * @returns {Buffer}
 */

SHA256.prototype._finish = function _finish(out) {
  writeU32(DESC, this.bytes >>> 29, 0);
  writeU32(DESC, this.bytes << 3, 4);

  this._update(PADDING, 1 + ((119 - (this.bytes % 64)) % 64));
  this._update(DESC, 8);

  for (let i = 0; i < 8; i++) {
    writeU32(out, this.s[i], i * 4);
    this.s[i] = 0;
  }

  return out;
};

/**
 * Transform SHA256 block.
 * @param {Buffer} chunk
 * @param {Number} pos
 */

SHA256.prototype.transform = function transform(chunk, pos) {
  let a = this.s[0];
  let b = this.s[1];
  let c = this.s[2];
  let d = this.s[3];
  let e = this.s[4];
  let f = this.s[5];
  let g = this.s[6];
  let h = this.s[7];
  let w = this.w;
  let i = 0;

  for (; i < 16; i++)
    w[i] = readU32(chunk, pos + i * 4);

  for (; i < 64; i++)
    w[i] = sigma1(w[i - 2]) + w[i - 7] + sigma0(w[i - 15]) + w[i - 16];

  for (i = 0; i < 64; i++) {
    let t1, t2;

    t1 = h + Sigma1(e);
    t1 += Ch(e, f, g);
    t1 += K[i] + w[i];

    t2 = Sigma0(a);
    t2 += Maj(a, b, c);

    h = g;
    g = f;
    f = e;

    e = d + t1;

    d = c;
    c = b;
    b = a;

    a = t1 + t2;
  }

  this.s[0] += a;
  this.s[1] += b;
  this.s[2] += c;
  this.s[3] += d;
  this.s[4] += e;
  this.s[5] += f;
  this.s[6] += g;
  this.s[7] += h;

  this.s[0] >>>= 0;
  this.s[1] >>>= 0;
  this.s[2] >>>= 0;
  this.s[3] >>>= 0;
  this.s[4] >>>= 0;
  this.s[5] >>>= 0;
  this.s[6] >>>= 0;
  this.s[7] >>>= 0;
};

/**
 * SHA256Hmac
 * @alias module:crypto/sha256.SHA256Hmac
 * @constructor
 * @property {SHA256} inner
 * @property {SHA256} outer
 */

function SHA256Hmac() {
  if (!(this instanceof SHA256Hmac))
    return new SHA256Hmac();

  this.inner = new SHA256();
  this.outer = new SHA256();
}

/**
 * Initialize HMAC context.
 * @param {Buffer} data
 */

SHA256Hmac.prototype.init = function init(data) {
  let key = BUFFER64;

  if (data.length > 64) {
    this.inner.init();
    this.inner.update(data);
    this.inner._finish(key);
    key.fill(0, 32, 64);
  } else {
    data.copy(key, 0);
    key.fill(0, data.length, 64);
  }

  for (let i = 0; i < key.length; i++)
    key[i] ^= 0x36;

  this.inner.init();
  this.inner.update(key);

  for (let i = 0; i < key.length; i++)
    key[i] ^= 0x6a;

  this.outer.init();
  this.outer.update(key);
};

/**
 * Update HMAC context.
 * @param {Buffer} data
 */

SHA256Hmac.prototype.update = function update(data) {
  this.inner.update(data);
};

/**
 * Finalize HMAC context.
 * @returns {Buffer}
 */

SHA256Hmac.prototype.finish = function finish() {
  this.outer.update(this.inner.finish());
  return this.outer.finish();
};

/*
 * Helpers
 * @see https://github.com/bitcoin-core/secp256k1/blob/master/src/hash_impl.h
 */

function Sigma0(x) {
  return (x >>> 2 | x << 30) ^ (x >>> 13 | x << 19) ^ (x >>> 22 | x << 10);
}

function Sigma1(x) {
  return (x >>> 6 | x << 26) ^ (x >>> 11 | x << 21) ^ (x >>> 25 | x << 7);
}

function sigma0(x) {
  return (x >>> 7 | x << 25) ^ (x >>> 18 | x << 14) ^ (x >>> 3);
}

function sigma1(x) {
  return (x >>> 17 | x << 15) ^ (x >>> 19 | x << 13) ^ (x >>> 10);
}

function Ch(x, y, z) {
  return z ^ (x & (y ^ z));
}

function Maj(x, y, z) {
  return (x & y) | (z & (x | y));
}

function writeU32(buf, value, offset) {
  buf[offset] = value >>> 24;
  buf[offset + 1] = (value >> 16) & 0xff;
  buf[offset + 2] = (value >> 8) & 0xff;
  buf[offset + 3] = value & 0xff;
}

function readU32(buf, offset) {
  return ((buf[offset] & 0xff) * 0x1000000)
    + ((buf[offset + 1] & 0xff) << 16)
    | ((buf[offset + 2] & 0xff) << 8)
    | (buf[offset + 3] & 0xff);
}

/*
 * Context Helpers
 */

const ctx = new SHA256();
const mctx = new SHA256Hmac();

/**
 * Hash buffer with sha256.
 * @alias module:crypto/sha256.sha256
 * @param {Buffer} data
 * @returns {Buffer}
 */

function sha256(data) {
  ctx.init();
  ctx.update(data);
  return ctx.finish();
}

/**
 * Hash buffer with double sha256.
 * @alias module:crypto/sha256.hash256
 * @param {Buffer} data
 * @returns {Buffer}
 */

function hash256(data) {
  let out = Buffer.allocUnsafe(32);
  ctx.init();
  ctx.update(data);
  ctx._finish(out);
  ctx.init();
  ctx.update(out);
  ctx._finish(out);
  return out;
}

/**
 * Create a sha256 HMAC from buffer and key.
 * @alias module:crypto/sha256.hmac
 * @param {Buffer} data
 * @param {Buffer} key
 * @returns {Buffer}
 */

function hmac(data, key) {
  mctx.init(key);
  mctx.update(data);
  return mctx.finish();
}

/*
 * Expose
 */

exports = SHA256;
exports.SHA256 = SHA256;
exports.SHA256Hmac = SHA256Hmac;
exports.digest = sha256;
exports.hmac = hmac;
exports.hash256 = hash256;

module.exports = exports;
