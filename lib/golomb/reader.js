/*!
 * reader.js - bit reader for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');
const {U64} = require('n64');

/**
 * Bit Reader
 */

class BitReader {
  /**
   * Create a bit reader.
   * @constructor
   * @ignore
   */

  constructor(data) {
    this.stream = data;
    this.pos = 0;
    this.remain = 8;
  }

  readBit() {
    if (this.pos >= this.stream.length)
      throw new Error('EOF');

    if (this.remain === 0) {
      this.pos += 1;

      if (this.pos >= this.stream.length)
        throw new Error('EOF');

      this.remain = 8;
    }

    this.remain -= 1;

    return (this.stream[this.pos] >> this.remain) & 1;
  }

  readByte() {
    if (this.pos >= this.stream.length)
      throw new Error('EOF');

    if (this.remain === 0) {
      this.pos += 1;

      if (this.pos >= this.stream.length)
        throw new Error('EOF');

      this.remain = 8;
    }

    if (this.remain === 8) {
      const ch = this.stream[this.pos];
      this.pos += 1;
      return ch;
    }

    let ch = this.stream[this.pos] & ((1 << this.remain) - 1);
    ch <<= 8 - this.remain;

    this.pos += 1;

    if (this.pos >= this.stream.length)
      throw new Error('EOF');

    ch |= this.stream[this.pos] >> this.remain;

    return ch;
  }

  readBits(count) {
    assert(count >= 0);
    assert(count <= 32);

    let num = 0;

    while (count >= 8) {
      num <<= 8;
      num |= this.readByte();
      count -= 8;
    }

    while (count > 0) {
      num <<= 1;
      num |= this.readBit();
      count -= 1;
    }

    return num;
  }

  readBits64(count) {
    assert(count >= 0);
    assert(count <= 64);

    const num = new U64();

    if (count > 32) {
      num.hi = this.readBits(count - 32);
      num.lo = this.readBits(32);
    } else {
      num.lo = this.readBits(count);
    }

    return num;
  }
}

/*
 * Expose
 */

module.exports = BitReader;
