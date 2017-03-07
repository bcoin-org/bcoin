/*!
 * chachapoly.js - chacha20/poly1305 for bcoin
 * Copyright (c) 2016-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var native = require('../utils/native').binding;

var BIG_ENDIAN = new Int8Array(new Int16Array([1]).buffer)[0] === 0;

/**
 * @module crypto/chachapoly
 */

/**
 * ChaCha20 (used for bip151)
 * @see https://tools.ietf.org/html/rfc7539#section-2
 * @alias module:crypto/chachapoly.ChaCha20
 * @constructor
 */

function ChaCha20() {
  if (!(this instanceof ChaCha20))
    return new ChaCha20();

  this.state = new Uint32Array(16);
  this.stream = new Uint32Array(16);
  this.bytes = new Uint8Array(this.stream.buffer);

  if (BIG_ENDIAN)
    this.bytes = new Buffer(64);

  this.pos = 0;
  this.ivSize = 0;
}

/**
 * Initialize chacha20 with a key, iv, and counter.
 * @param {Buffer} key
 * @param {Buffer} iv
 * @param {Number} counter
 */

ChaCha20.prototype.init = function init(key, iv, counter) {
  if (key)
    this.initKey(key);

  if (iv)
    this.initIV(iv, counter);
};

/**
 * Set key.
 * @param {Buffer} key
 */

ChaCha20.prototype.initKey = function initKey(key) {
  this.state[0] = 0x61707865;
  this.state[1] = 0x3320646e;
  this.state[2] = 0x79622d32;
  this.state[3] = 0x6b206574;

  this.state[4] = key.readUInt32LE(0, true);
  this.state[5] = key.readUInt32LE(4, true);
  this.state[6] = key.readUInt32LE(8, true);
  this.state[7] = key.readUInt32LE(12, true);
  this.state[8] = key.readUInt32LE(16, true);
  this.state[9] = key.readUInt32LE(20, true);
  this.state[10] = key.readUInt32LE(24, true);
  this.state[11] = key.readUInt32LE(28, true);

  this.state[12] = 0;

  this.pos = 0xffffffff;
};

/**
 * Set IV and counter.
 * @param {Buffer} iv
 * @param {Number} counter
 */

ChaCha20.prototype.initIV = function initIV(iv, counter) {
  if (iv.length === 8) {
    this.state[13] = 0;
    this.state[14] = iv.readUInt32LE(0, true);
    this.state[15] = iv.readUInt32LE(4, true);
  } else if (iv.length === 12) {
    this.state[13] = iv.readUInt32LE(0, true);
    this.state[14] = iv.readUInt32LE(4, true);
    this.state[15] = iv.readUInt32LE(8, true);
  } else {
    assert(false, 'Bad iv size.');
  }

  this.ivSize = iv.length * 8;

  this.setCounter(counter);
};

/**
 * Encrypt/decrypt data.
 * @param {Buffer} data - Will be mutated.
 */

ChaCha20.prototype.encrypt = function encrypt(data) {
  var i, j;

  for (i = 0; i < data.length; i++) {
    if (this.pos >= 64) {
      for (j = 0; j < 16; j++)
        this.stream[j] = this.state[j];

      for (j = 0; j < 10; j++) {
        qround(this.stream, 0, 4, 8, 12);
        qround(this.stream, 1, 5, 9, 13);
        qround(this.stream, 2, 6, 10, 14);
        qround(this.stream, 3, 7, 11, 15);
        qround(this.stream, 0, 5, 10, 15);
        qround(this.stream, 1, 6, 11, 12);
        qround(this.stream, 2, 7, 8, 13);
        qround(this.stream, 3, 4, 9, 14);
      }

      for (j = 0; j < 16; j++) {
        this.stream[j] += this.state[j];
        if (BIG_ENDIAN)
          this.bytes.writeUInt32LE(this.stream[j], j * 4, true);
      }

      this.state[12]++;

      if (this.state[12] === 0) {
        assert(this.ivSize === 64, 'Counter overflow.');
        this.state[13]++;
        assert(this.state[13] !== 0, 'Counter overflow.');
      }

      this.pos = 0;
    }

    data[i] ^= this.bytes[this.pos++];
  }

  return data;
};

/**
 * Artificially set the counter.
 * @param {Number} counter
 */

ChaCha20.prototype.setCounter = function setCounter(counter) {
  var lo, hi;

  if (!counter)
    counter = 0;

  lo = counter % 0x100000000;
  hi = (counter - lo) / 0x100000000;

  this.state[12] = lo;

  if (this.ivSize === 64)
    this.state[13] = hi;
};

/**
 * Get the counter as a uint64.
 * @returns {Number}
 */

ChaCha20.prototype.getCounter = function getCounter() {
  var lo = this.state[12];
  var hi = this.state[13];
  if (this.ivSize === 64)
    return hi * 0x100000000 + lo;
  return lo;
};

if (native)
  ChaCha20 = native.ChaCha20;

/*
 * Helpers
 */

function qround(x, a, b, c, d) {
  x[a] += x[b];
  x[d] = rotl32(x[d] ^ x[a], 16);

  x[c] += x[d];
  x[b] = rotl32(x[b] ^ x[c], 12);

  x[a] += x[b];
  x[d] = rotl32(x[d] ^ x[a], 8);

  x[c] += x[d];
  x[b] = rotl32(x[b] ^ x[c], 7);
}

function rotl32(w, b) {
  return (w << b) | (w >>> (32 - b));
}

/**
 * Poly1305 (used for bip151)
 * @see https://github.com/floodyberry/poly1305-donna
 * @see https://tools.ietf.org/html/rfc7539#section-2.5
 * @alias module:crypto/chachapoly.Poly1305
 * @constructor
 */

function Poly1305() {
  if (!(this instanceof Poly1305))
    return new Poly1305();

  this.r = new Uint16Array(10);
  this.h = new Uint16Array(10);
  this.pad = new Uint16Array(8);
  this.fin = 0;
  this.leftover = 0;
  this.buffer = new Buffer(16);
}

/**
 * Initialize poly1305 with a key.
 * @param {Buffer} key
 */

Poly1305.prototype.init = function init(key) {
  var t0, t1, t2, t3, t4, t5, t6, t7, i;

  // r &= 0xffffffc0ffffffc0ffffffc0fffffff
  t0 = key.readUInt16LE(0, true);
  t1 = key.readUInt16LE(2, true);
  t2 = key.readUInt16LE(4, true);
  t3 = key.readUInt16LE(6, true);
  t4 = key.readUInt16LE(8, true);
  t5 = key.readUInt16LE(10, true);
  t6 = key.readUInt16LE(12, true);
  t7 = key.readUInt16LE(14, true);

  this.r[0] = t0 & 0x1fff;
  this.r[1] = ((t0 >>> 13) | (t1 << 3)) & 0x1fff;
  this.r[2] = ((t1 >>> 10) | (t2 << 6)) & 0x1f03;
  this.r[3] = ((t2 >>> 7) | (t3 << 9)) & 0x1fff;
  this.r[4] = ((t3 >>> 4) | (t4 << 12)) & 0x00ff;
  this.r[5] = (t4 >>> 1) & 0x1ffe;
  this.r[6] = ((t4 >>> 14) | (t5 << 2)) & 0x1fff;
  this.r[7] = ((t5 >>> 11) | (t6 << 5)) & 0x1f81;
  this.r[8] = ((t6 >>> 8) | (t7 << 8)) & 0x1fff;
  this.r[9] = (t7 >>> 5) & 0x007f;

  // h = 0
  for (i = 0; i < 10; i++)
    this.h[i] = 0;

  // save pad for later
  for (i = 0; i < 8; i++)
    this.pad[i] = key.readUInt16LE(16 + (2 * i), true);

  this.leftover = 0;
  this.fin = 0;
};

/**
 * Process 16 byte blocks.
 * @param {Buffer} data - Blocks.
 * @param {Number} bytes - Size.
 * @param {Number} m - Offset pointer.
 */

Poly1305.prototype.blocks = function blocks(data, bytes, m) {
  var hibit = this.fin ? 0 : (1 << 11); // 1 << 128
  var d = new Uint32Array(10);
  var i, j, t0, t1, t2, t3, t4, t5, t6, t7, c;

  while (bytes >= 16) {
    // h += m[i]
    t0 = data.readUInt16LE(m + 0, true);
    t1 = data.readUInt16LE(m + 2, true);
    t2 = data.readUInt16LE(m + 4, true);
    t3 = data.readUInt16LE(m + 6, true);
    t4 = data.readUInt16LE(m + 8, true);
    t5 = data.readUInt16LE(m + 10, true);
    t6 = data.readUInt16LE(m + 12, true);
    t7 = data.readUInt16LE(m + 14, true);

    this.h[0] += t0 & 0x1fff;
    this.h[1] += ((t0 >>> 13) | (t1 << 3)) & 0x1fff;
    this.h[2] += ((t1 >>> 10) | (t2 << 6)) & 0x1fff;
    this.h[3] += ((t2 >>> 7) | (t3 << 9)) & 0x1fff;
    this.h[4] += ((t3 >>> 4) | (t4 << 12)) & 0x1fff;
    this.h[5] += ((t4 >>> 1)) & 0x1fff;
    this.h[6] += ((t4 >>> 14) | (t5 << 2)) & 0x1fff;
    this.h[7] += ((t5 >>> 11) | (t6 << 5)) & 0x1fff;
    this.h[8] += ((t6 >>> 8) | (t7 << 8)) & 0x1fff;
    this.h[9] += ((t7 >>> 5)) | hibit;

    // h *= r, (partial) h %= p
    for (i = 0, c = 0; i < 10; i++) {
      d[i] = c;
      for (j = 0; j < 10; j++) {
        d[i] += this.h[j] * (j <= i
          ? this.r[i - j]
          : 5 * this.r[i + 10 - j]);
        // Sum(h[i] * r[i] * 5) will overflow slightly
        // above 6 products with an unclamped r, so
        // carry at 5
        if (j === 4) {
          c = d[i] >>> 13;
          d[i] &= 0x1fff;
        }
      }
      c += d[i] >>> 13;
      d[i] &= 0x1fff;
    }
    c = (c << 2) + c; // c *= 5
    c += d[0];
    d[0] = (c & 0x1fff);
    c = c >>> 13;
    d[1] += c;

    for (i = 0; i < 10; i++)
      this.h[i] = d[i];

    m += 16;
    bytes -= 16;
  }
};

/**
 * Update the MAC with data (will be
 * processed as 16 byte blocks).
 * @param {Buffer} data
 */

Poly1305.prototype.update = function update(data) {
  var bytes = data.length;
  var m = 0;
  var i, want;

  // handle leftover
  if (this.leftover) {
    want = 16 - this.leftover;
    if (want > bytes)
      want = bytes;
    for (i = 0; i < want; i++)
      this.buffer[this.leftover + i] = data[m + i];
    bytes -= want;
    m += want;
    this.leftover += want;
    if (this.leftover < 16)
      return;
    this.blocks(this.buffer, 16, 0);
    this.leftover = 0;
  }

  // process full blocks
  if (bytes >= 16) {
    want = bytes & ~(16 - 1);
    this.blocks(data, want, m);
    m += want;
    bytes -= want;
  }

  // store leftover
  if (bytes) {
    for (i = 0; i < bytes; i++)
      this.buffer[this.leftover + i] = data[m + i];
    this.leftover += bytes;
  }
};

/**
 * Finalize and return a 16-byte MAC.
 * @returns {Buffer}
 */

Poly1305.prototype.finish = function finish() {
  var mac = new Buffer(16);
  var g = new Uint16Array(10);
  var c, mask, f, i;

  // process the remaining block
  if (this.leftover) {
    i = this.leftover;
    this.buffer[i++] = 1;
    for (; i < 16; i++)
      this.buffer[i] = 0;
    this.fin = 1;
    this.blocks(this.buffer, 16, 0);
  }

  // fully carry h
  c = this.h[1] >>> 13;
  this.h[1] &= 0x1fff;
  for (i = 2; i < 10; i++) {
    this.h[i] += c;
    c = this.h[i] >>> 13;
    this.h[i] &= 0x1fff;
  }
  this.h[0] += c * 5;
  c = this.h[0] >>> 13;
  this.h[0] &= 0x1fff;
  this.h[1] += c;
  c = this.h[1] >>> 13;
  this.h[1] &= 0x1fff;
  this.h[2] += c;

  // compute h + -p
  g[0] = this.h[0] + 5;
  c = g[0] >>> 13;
  g[0] &= 0x1fff;
  for (i = 1; i < 10; i++) {
    g[i] = this.h[i] + c;
    c = g[i] >>> 13;
    g[i] &= 0x1fff;
  }

  // select h if h < p, or h + -p if h >= p
  mask = (c ^ 1) - 1;
  for (i = 0; i < 10; i++)
    g[i] &= mask;
  mask = ~mask;
  for (i = 0; i < 10; i++)
    this.h[i] = (this.h[i] & mask) | g[i];

  // h = h % (2^128)
  this.h[0] = ((this.h[0]) | (this.h[1] << 13)) & 0xffff;
  this.h[1] = ((this.h[1] >>> 3) | (this.h[2] << 10)) & 0xffff;
  this.h[2] = ((this.h[2] >>> 6) | (this.h[3] << 7)) & 0xffff;
  this.h[3] = ((this.h[3] >>> 9) | (this.h[4] << 4)) & 0xffff;
  this.h[4] = ((this.h[4] >>> 12)
    | (this.h[5] << 1) | (this.h[6] << 14)) & 0xffff;
  this.h[5] = ((this.h[6] >>> 2) | (this.h[7] << 11)) & 0xffff;
  this.h[6] = ((this.h[7] >>> 5) | (this.h[8] << 8)) & 0xffff;
  this.h[7] = ((this.h[8] >>> 8) | (this.h[9] << 5)) & 0xffff;

  // mac = (h + pad) % (2^128)
  f = this.h[0] + this.pad[0];
  this.h[0] = f;
  for (i = 1; i < 8; i++) {
    f = this.h[i] + this.pad[i] + (f >>> 16);
    this.h[i] = f;
  }

  for (i = 0; i < 8; i++)
    mac.writeUInt16LE(this.h[i], i * 2, true);

  // zero out the state
  for (i = 0; i < 10; i++)
    this.h[i] = 0;
  for (i = 0; i < 10; i++)
    this.r[i] = 0;
  for (i = 0; i < 8; i++)
    this.pad[i] = 0;

  return mac;
};

/**
 * Return a MAC for a message and key.
 * @param {Buffer} msg
 * @param {Buffer} key
 * @returns {Buffer} MAC
 */

Poly1305.auth = function auth(msg, key) {
  var poly = new Poly1305();
  poly.init(key);
  poly.update(msg);
  return poly.finish();
};

/**
 * Compare two MACs in constant time.
 * @param {Buffer} mac1
 * @param {Buffer} mac2
 * @returns {Boolean}
 */

Poly1305.verify = function verify(mac1, mac2) {
  var dif = 0;
  var i;

  // Compare in constant time.
  for (i = 0; i < 16; i++)
    dif |= mac1[i] ^ mac2[i];

  dif = (dif - 1) >>> 31;

  return (dif & 1) !== 0;
};

if (native)
  Poly1305 = native.Poly1305;

/**
 * AEAD (used for bip151)
 * @exports AEAD
 * @see https://github.com/openssh/openssh-portable
 * @see https://tools.ietf.org/html/rfc7539#section-2.8
 * @alias module:crypto/chachapoly.AEAD
 * @constructor
 */

function AEAD() {
  if (!(this instanceof AEAD))
    return new AEAD();

  this.chacha20 = new ChaCha20();
  this.poly1305 = new Poly1305();
  this.aadLen = 0;
  this.cipherLen = 0;
  this.polyKey = null;
}

/**
 * Initialize the AEAD with a key and iv.
 * @param {Buffer} key
 * @param {Buffer} iv - IV / packet sequence number.
 */

AEAD.prototype.init = function init(key, iv) {
  var polyKey = new Buffer(32);
  polyKey.fill(0);

  this.chacha20.init(key, iv);
  this.chacha20.encrypt(polyKey);
  this.poly1305.init(polyKey);

  // We need to encrypt a full block
  // to get the cipher in the correct state.
  this.chacha20.encrypt(new Buffer(32));

  // Counter should be one.
  assert(this.chacha20.getCounter() === 1);

  // Expose for debugging.
  this.polyKey = polyKey;

  this.aadLen = 0;
  this.cipherLen = 0;
};

/**
 * Update the aad (will be finalized
 * on an encrypt/decrypt call).
 * @param {Buffer} aad
 */

AEAD.prototype.aad = function _aad(aad) {
  assert(this.cipherLen === 0, 'Cannot update aad.');
  this.poly1305.update(aad);
  this.aadLen += aad.length;
};

/**
 * Encrypt a piece of data.
 * @param {Buffer} data
 */

AEAD.prototype.encrypt = function encrypt(data) {
  if (this.cipherLen === 0)
    this.pad16(this.aadLen);

  this.chacha20.encrypt(data);
  this.poly1305.update(data);
  this.cipherLen += data.length;

  return data;
};

/**
 * Decrypt a piece of data.
 * @param {Buffer} data
 */

AEAD.prototype.decrypt = function decrypt(data) {
  if (this.cipherLen === 0)
    this.pad16(this.aadLen);

  this.cipherLen += data.length;
  this.poly1305.update(data);
  this.chacha20.encrypt(data);

  return data;
};

/**
 * Authenticate data without decrypting.
 * @param {Buffer} data
 */

AEAD.prototype.auth = function auth(data) {
  if (this.cipherLen === 0)
    this.pad16(this.aadLen);

  this.cipherLen += data.length;
  this.poly1305.update(data);

  return data;
};

/**
 * Finalize the aead and generate a MAC.
 * @returns {Buffer} MAC
 */

AEAD.prototype.finish = function finish() {
  var len = new Buffer(16);
  var lo, hi;

  // The RFC says these are supposed to be
  // uint32le, but their own fucking test
  // cases fail unless they are uint64le's.
  lo = this.aadLen % 0x100000000;
  hi = (this.aadLen - lo) / 0x100000000;
  len.writeUInt32LE(lo, 0, true);
  len.writeUInt32LE(hi, 4, true);

  lo = this.cipherLen % 0x100000000;
  hi = (this.cipherLen - lo) / 0x100000000;
  len.writeUInt32LE(lo, 8, true);
  len.writeUInt32LE(hi, 12, true);

  if (this.cipherLen === 0)
    this.pad16(this.aadLen);

  this.pad16(this.cipherLen);
  this.poly1305.update(len);

  return this.poly1305.finish();
};

/**
 * Pad a chunk before updating mac.
 * @private
 * @param {Number} size
 */

AEAD.prototype.pad16 = function pad16(size) {
  var pad;

  size %= 16;

  if (size === 0)
    return;

  pad = new Buffer(16 - size);
  pad.fill(0);

  this.poly1305.update(pad);
};

/*
 * Expose
 */

exports.ChaCha20 = ChaCha20;
exports.Poly1305 = Poly1305;
exports.AEAD = AEAD;
