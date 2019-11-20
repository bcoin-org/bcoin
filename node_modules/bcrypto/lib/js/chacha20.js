/*!
 * chacha20.js - chacha20 for bcrypto
 * Copyright (c) 2016-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');

const BIG_ENDIAN = new Int8Array(new Int16Array([1]).buffer)[0] === 0;

/**
 * ChaCha20
 * @see https://tools.ietf.org/html/rfc7539#section-2
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

  init(key, iv, counter) {
    this.initKey(key);
    this.initIV(iv, counter);
    return this;
  }

  /**
   * Set key.
   * @param {Buffer} key
   */

  initKey(key) {
    assert(Buffer.isBuffer(key) && key.length >= 32);

    this.state[0] = 0x61707865;
    this.state[1] = 0x3320646e;
    this.state[2] = 0x79622d32;
    this.state[3] = 0x6b206574;

    this.state[4] = readU32(key, 0);
    this.state[5] = readU32(key, 4);
    this.state[6] = readU32(key, 8);
    this.state[7] = readU32(key, 12);
    this.state[8] = readU32(key, 16);
    this.state[9] = readU32(key, 20);
    this.state[10] = readU32(key, 24);
    this.state[11] = readU32(key, 28);

    this.state[12] = 0;

    this.pos = 0xffffffff;

    return this;
  }

  /**
   * Set IV and counter.
   * @param {Buffer} iv
   * @param {Number} counter
   */

  initIV(iv, counter) {
    assert(Buffer.isBuffer(iv) && iv.length >= 8);

    if (iv.length === 16) {
      this.state[12] = readU32(iv, 0);
      this.state[13] = readU32(iv, 4);
      this.state[14] = readU32(iv, 8);
      this.state[15] = readU32(iv, 12);
      this.ivSize = 12;
      return this;
    }

    if (iv.length === 8) {
      this.state[13] = 0;
      this.state[14] = readU32(iv, 0);
      this.state[15] = readU32(iv, 4);
    } else if (iv.length === 12) {
      this.state[13] = readU32(iv, 0);
      this.state[14] = readU32(iv, 4);
      this.state[15] = readU32(iv, 8);
    } else {
      assert(false, 'Bad iv size.');
    }

    this.ivSize = iv.length;

    this.setCounter(counter);

    return this;
  }

  /**
   * Encrypt/decrypt data.
   * @param {Buffer} data - Will be mutated.
   */

  encrypt(data) {
    return this.crypt(data, data);
  }

  /**
   * Encrypt/decrypt data.
   * @param {Buffer} input
   * @param {Buffer} output
   */

  crypt(input, output) {
    assert(Buffer.isBuffer(input));
    assert(Buffer.isBuffer(output));

    if (output.length < input.length)
      throw new Error('Invalid output size.');

    for (let i = 0; i < input.length; i++) {
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
            writeU32(this.bytes, this.stream[j], j * 4);
        }

        this.state[12] += 1;

        if (this.state[12] === 0)
          this.state[13] += 1;

        this.pos = 0;
      }

      output[i] = input[i] ^ this.bytes[this.pos++];
    }

    return output;
  }

  /**
   * Artificially set the counter.
   * @param {Number} counter
   */

  setCounter(counter) {
    if (counter == null)
      counter = 0;

    assert(Number.isSafeInteger(counter) && counter >= 0);

    const lo = counter % 0x100000000;
    const hi = (counter - lo) / 0x100000000;

    this.state[12] = lo;

    if (this.ivSize === 8)
      this.state[13] = hi;

    return this;
  }

  /**
   * Get the counter as a uint64.
   * @returns {Number}
   */

  getCounter() {
    const lo = this.state[12];
    const hi = this.state[13];
    if (this.ivSize === 8)
      return hi * 0x100000000 + lo;
    return lo;
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

    this.pos = 0;
    this.ivSize = 0;

    return this;
  }
}

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
