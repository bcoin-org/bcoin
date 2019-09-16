/*!
 * writer.js - bit writer for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');

/**
 * Bit Writer - as specified by BIP 158 for Golomb Rice Coding
 * @see https://github.com/bitcoin/bips/blob/master/bip-0158.mediawiki#golomb-rice-coding
 */

class BitWriter {
  /**
   * Create a bit writer.
   * @constructor
   * @ignore
   */

  constructor() {
    this.stream = [];
    this.remain = 0;
  }

  /**
   * Write bit.
   * @param {Buffer} bit
   */

  writeBit(bit) {
    if (this.remain === 0) {
      this.stream.push(0);
      this.remain = 8;
    }

    if (bit) {
      const index = this.stream.length - 1;
      this.stream[index] |= 1 << (this.remain - 1);
    }

    this.remain--;
  }

  /**
   * Write byte.
   * @param {Buffer} ch
   */

  writeByte(ch) {
    if (this.remain === 0) {
      this.stream.push(0);
      this.remain = 8;
    }

    const index = this.stream.length - 1;

    this.stream[index] |= (ch >> (8 - this.remain)) & 0xff;
    this.stream.push(0);
    this.stream[index + 1] = (ch << this.remain) & 0xff;
  }

  /**
   * Write bits.
   * @param {Number} num
   * @param {Number} count
   */

  writeBits(num, count) {
    assert(count >= 0);
    assert(count <= 32);

    num <<= 32 - count;

    while (count >= 8) {
      const ch = num >>> 24;
      this.writeByte(ch);
      num <<= 8;
      count -= 8;
    }

    while (count > 0) {
      const bit = num >>> 31;
      this.writeBit(bit);
      num <<= 1;
      count -= 1;
    }
  }

  /**
   * Write bits. 64-bit.
   * @param {Number} num
   * @param {Number} count
   */

  writeBits64(num, count) {
    assert(count >= 0);
    assert(count <= 64);

    if (count > 32) {
      this.writeBits(num.hi, count - 32);
      this.writeBits(num.lo, 32);
    } else {
      this.writeBits(num.lo, count);
    }
  }

  /**
   * Allocate and render the final buffer.
   * @returns {Buffer} Rendered buffer.
   */

  render() {
    const data = Buffer.allocUnsafe(this.stream.length);

    for (let i = 0; i < this.stream.length; i++)
      data[i] = this.stream[i];

    return data;
  }
}

/*
 * Expose
 */

module.exports = BitWriter;
