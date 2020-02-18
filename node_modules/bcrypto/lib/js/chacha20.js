/*!
 * chacha20.js - chacha20 for bcrypto
 * Copyright (c) 2016-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources
 *   https://en.wikipedia.org/wiki/Chacha20
 *   https://tools.ietf.org/html/rfc7539#section-2
 *   https://cr.yp.to/chacha.html
 */

'use strict';

const assert = require('../internal/assert');

/*
 * Constants
 */

const BIG_ENDIAN = new Int8Array(new Int16Array([1]).buffer)[0] === 0;

/**
 * ChaCha20
 */

class ChaCha20 {
  /**
   * Create a ChaCha20 context.
   * @constructor
   */

  constructor() {
    this.state = new Uint32Array(16);
    this.stream = new Uint32Array(16);
    this.bytes = new Uint8Array(this.stream.buffer);
    this.pos = -1;

    if (BIG_ENDIAN)
      this.bytes = Buffer.alloc(64);
  }

  /**
   * Initialize chacha20 with a key, nonce, and counter.
   * @param {Buffer} key
   * @param {Buffer} nonce
   * @param {Number} counter
   */

  init(key, nonce, counter) {
    if (counter == null)
      counter = 0;

    assert(Buffer.isBuffer(key));
    assert(Buffer.isBuffer(nonce));
    assert(Number.isSafeInteger(counter));

    if (key.length !== 16 && key.length !== 32)
      throw new RangeError('Invalid key size.');

    if (nonce.length >= 24) {
      key = ChaCha20.derive(key, nonce.slice(0, 16));
      nonce = nonce.slice(16);
    }

    this.state[0] = 0x61707865;
    this.state[1] = key.length < 32 ? 0x3120646e : 0x3320646e;
    this.state[2] = key.length < 32 ? 0x79622d36 : 0x79622d32;
    this.state[3] = 0x6b206574;
    this.state[4] = readU32(key, 0);
    this.state[5] = readU32(key, 4);
    this.state[6] = readU32(key, 8);
    this.state[7] = readU32(key, 12);
    this.state[8] = readU32(key, 16 % key.length);
    this.state[9] = readU32(key, 20 % key.length);
    this.state[10] = readU32(key, 24 % key.length);
    this.state[11] = readU32(key, 28 % key.length);
    this.state[12] = counter >>> 0;

    if (nonce.length === 8) {
      this.state[13] = (counter / 0x100000000) >>> 0;
      this.state[14] = readU32(nonce, 0);
      this.state[15] = readU32(nonce, 4);
    } else if (nonce.length === 12) {
      this.state[13] = readU32(nonce, 0);
      this.state[14] = readU32(nonce, 4);
      this.state[15] = readU32(nonce, 8);
    } else if (nonce.length === 16) {
      this.state[12] = readU32(nonce, 0);
      this.state[13] = readU32(nonce, 4);
      this.state[14] = readU32(nonce, 8);
      this.state[15] = readU32(nonce, 12);
    } else {
      throw new RangeError('Invalid nonce size.');
    }

    this.pos = 0;

    return this;
  }

  /**
   * Encrypt/decrypt data.
   * @param {Buffer} data - Will be mutated.
   * @returns {Buffer}
   */

  encrypt(data) {
    assert(Buffer.isBuffer(data));

    if (this.pos === -1)
      throw new Error('Context is not initialized.');

    for (let i = 0; i < data.length; i++) {
      if ((this.pos & 63) === 0) {
        this._block();
        this.pos = 0;
      }

      data[i] ^= this.bytes[this.pos++];
    }

    return data;
  }

  /**
   * Stir the stream.
   */

  _block() {
    for (let i = 0; i < 16; i++)
      this.stream[i] = this.state[i];

    for (let i = 0; i < 10; i++) {
      qround(this.stream, 0, 4, 8, 12);
      qround(this.stream, 1, 5, 9, 13);
      qround(this.stream, 2, 6, 10, 14);
      qround(this.stream, 3, 7, 11, 15);
      qround(this.stream, 0, 5, 10, 15);
      qround(this.stream, 1, 6, 11, 12);
      qround(this.stream, 2, 7, 8, 13);
      qround(this.stream, 3, 4, 9, 14);
    }

    for (let i = 0; i < 16; i++)
      this.stream[i] += this.state[i];

    if (BIG_ENDIAN) {
      for (let i = 0; i < 16; i++)
        writeU32(this.bytes, this.stream[i], i * 4);
    }

    this.state[12] += 1;

    if (this.state[12] === 0)
      this.state[13] += 1;
  }

  /**
   * Destroy context.
   */

  destroy() {
    for (let i = 0; i < 16; i++) {
      this.state[i] = 0;
      this.stream[i] = 0;
    }

    if (BIG_ENDIAN) {
      for (let i = 0; i < 64; i++)
        this.bytes[i] = 0;
    }

    this.pos = -1;

    return this;
  }

  /**
   * Derive key with XChaCha20.
   * @param {Buffer} key
   * @param {Buffer} nonce
   * @returns {Buffer}
   */

  static derive(key, nonce) {
    assert(Buffer.isBuffer(key));
    assert(Buffer.isBuffer(nonce));

    if (key.length !== 16 && key.length !== 32)
      throw new RangeError('Invalid key size.');

    if (nonce.length !== 16)
      throw new RangeError('Invalid nonce size.');

    const state = new Uint32Array(16);

    state[0] = 0x61707865;
    state[1] = key.length < 32 ? 0x3120646e : 0x3320646e;
    state[2] = key.length < 32 ? 0x79622d36 : 0x79622d32;
    state[3] = 0x6b206574;
    state[4] = readU32(key, 0);
    state[5] = readU32(key, 4);
    state[6] = readU32(key, 8);
    state[7] = readU32(key, 12);
    state[8] = readU32(key, 16 % key.length);
    state[9] = readU32(key, 20 % key.length);
    state[10] = readU32(key, 24 % key.length);
    state[11] = readU32(key, 28 % key.length);
    state[12] = readU32(nonce, 0);
    state[13] = readU32(nonce, 4);
    state[14] = readU32(nonce, 8);
    state[15] = readU32(nonce, 12);

    for (let i = 0; i < 10; i++) {
      qround(state, 0, 4, 8, 12);
      qround(state, 1, 5, 9, 13);
      qround(state, 2, 6, 10, 14);
      qround(state, 3, 7, 11, 15);
      qround(state, 0, 5, 10, 15);
      qround(state, 1, 6, 11, 12);
      qround(state, 2, 7, 8, 13);
      qround(state, 3, 4, 9, 14);
    }

    const out = Buffer.alloc(32);

    writeU32(out, state[0], 0);
    writeU32(out, state[1], 4);
    writeU32(out, state[2], 8);
    writeU32(out, state[3], 12);
    writeU32(out, state[12], 16);
    writeU32(out, state[13], 20);
    writeU32(out, state[14], 24);
    writeU32(out, state[15], 28);

    return out;
  }
}

/*
 * Static
 */

ChaCha20.native = 0;

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

module.exports = ChaCha20;
