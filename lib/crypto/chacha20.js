/*!
 * chacha20.js - chacha20 for bcoin
 * Copyright (c) 2016-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const native = require('../native').binding;

const BIG_ENDIAN = new Int8Array(new Int16Array([1]).buffer)[0] === 0;

/**
 * ChaCha20 (used for bip151)
 * @alias module:crypto.ChaCha20
 * @constructor
 * @see https://tools.ietf.org/html/rfc7539#section-2
 */

function ChaCha20() {
  if (!(this instanceof ChaCha20))
    return new ChaCha20();

  this.state = new Uint32Array(16);
  this.stream = new Uint32Array(16);
  this.bytes = new Uint8Array(this.stream.buffer);

  if (BIG_ENDIAN)
    this.bytes = Buffer.allocUnsafe(64);

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
  for (let i = 0; i < data.length; i++) {
    if (this.pos >= 64) {
      for (let j = 0; j < 16; j++)
        this.stream[j] = this.state[j];

      for (let j = 0; j < 10; j++) {
        qround(this.stream, 0, 4, 8, 12);
        qround(this.stream, 1, 5, 9, 13);
        qround(this.stream, 2, 6, 10, 14);
        qround(this.stream, 3, 7, 11, 15);
        qround(this.stream, 0, 5, 10, 15);
        qround(this.stream, 1, 6, 11, 12);
        qround(this.stream, 2, 7, 8, 13);
        qround(this.stream, 3, 4, 9, 14);
      }

      for (let j = 0; j < 16; j++) {
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
  let lo, hi;

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
  let lo = this.state[12];
  let hi = this.state[13];
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

/*
 * Expose
 */

module.exports = ChaCha20;
