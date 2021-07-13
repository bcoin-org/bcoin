/*!
 * staticwriter.js - buffer writer for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const enforce = require('./enforce');
const encoding = require('./encoding');
const EncodingError = require('./error');

/*
 * Constants
 */

const EMPTY = Buffer.alloc(0);
const POOL_SIZE = 100 << 10;

let POOL = null;

/**
 * Statically Allocated Writer
 */

class StaticWriter {
  /**
   * Statically allocated buffer writer.
   * @constructor
   * @param {Number|Buffer} options
   */

  constructor(options) {
    this.data = EMPTY;
    this.offset = 0;

    if (options != null)
      this.init(options);
  }

  /**
   * Assertion.
   * @param {Number} size
   */

  check(size) {
    if (this.offset + size > this.data.length)
      throw new EncodingError(this.offset, 'Out of bounds write', this.check);
  }

  /**
   * Initialize options.
   * @param {Object} options
   */

  init(options) {
    if (Buffer.isBuffer(options)) {
      this.data = options;
      this.offset = 0;
      return this;
    }

    enforce((options >>> 0) === options, 'size', 'integer');

    this.data = Buffer.allocUnsafeSlow(options);
    this.offset = 0;

    return this;
  }

  /**
   * Allocate writer from preallocated 100kb pool.
   * @param {Number} size
   * @returns {StaticWriter}
   */

  static pool(size) {
    enforce((size >>> 0) === size, 'size', 'integer');

    if (size <= POOL_SIZE) {
      if (!POOL)
        POOL = Buffer.allocUnsafeSlow(POOL_SIZE);

      const bw = new StaticWriter();

      bw.data = POOL.slice(0, size);

      return bw;
    }

    return new StaticWriter(size);
  }

  /**
   * Allocate and render the final buffer.
   * @returns {Buffer} Rendered buffer.
   */

  render() {
    const {data, offset} = this;

    if (offset !== data.length)
      throw new EncodingError(offset, 'Out of bounds write');

    this.destroy();

    return data;
  }

  /**
   * Slice the final buffer at written offset.
   * @returns {Buffer} Rendered buffer.
   */

  slice() {
    const {data, offset} = this;

    if (offset > data.length)
      throw new EncodingError(offset, 'Out of bounds write');

    this.destroy();

    return data.slice(0, offset);
  }

  /**
   * Get size of data written so far.
   * @returns {Number}
   */

  getSize() {
    return this.offset;
  }

  /**
   * Seek to relative offset.
   * @param {Number} off
   */

  seek(off) {
    enforce(Number.isSafeInteger(off), 'off', 'integer');

    if (this.offset + off < 0)
      throw new EncodingError(this.offset, 'Out of bounds write');

    this.check(off);
    this.offset += off;

    return this;
  }

  /**
   * Destroy the buffer writer.
   */

  destroy() {
    this.data = EMPTY;
    this.offset = 0;
    return this;
  }

  /**
   * Write uint8.
   * @param {Number} value
   */

  writeU8(value) {
    this.check(1);
    this.offset = encoding.writeU8(this.data, value, this.offset);
    return this;
  }

  /**
   * Write uint16le.
   * @param {Number} value
   */

  writeU16(value) {
    this.check(2);
    this.offset = encoding.writeU16(this.data, value, this.offset);
    return this;
  }

  /**
   * Write uint16be.
   * @param {Number} value
   */

  writeU16BE(value) {
    this.check(2);
    this.offset = encoding.writeU16BE(this.data, value, this.offset);
    return this;
  }

  /**
   * Write uint24le.
   * @param {Number} value
   */

  writeU24(value) {
    this.check(3);
    this.offset = encoding.writeU24(this.data, value, this.offset);
    return this;
  }

  /**
   * Write uint24be.
   * @param {Number} value
   */

  writeU24BE(value) {
    this.check(3);
    this.offset = encoding.writeU24BE(this.data, value, this.offset);
    return this;
  }

  /**
   * Write uint32le.
   * @param {Number} value
   */

  writeU32(value) {
    this.check(4);
    this.offset = encoding.writeU32(this.data, value, this.offset);
    return this;
  }

  /**
   * Write uint32be.
   * @param {Number} value
   */

  writeU32BE(value) {
    this.check(4);
    this.offset = encoding.writeU32BE(this.data, value, this.offset);
    return this;
  }

  /**
   * Write uint40le.
   * @param {Number} value
   */

  writeU40(value) {
    this.check(5);
    this.offset = encoding.writeU40(this.data, value, this.offset);
    return this;
  }

  /**
   * Write uint40be.
   * @param {Number} value
   */

  writeU40BE(value) {
    this.check(5);
    this.offset = encoding.writeU40BE(this.data, value, this.offset);
    return this;
  }

  /**
   * Write uint48le.
   * @param {Number} value
   */

  writeU48(value) {
    this.check(6);
    this.offset = encoding.writeU48(this.data, value, this.offset);
    return this;
  }

  /**
   * Write uint48be.
   * @param {Number} value
   */

  writeU48BE(value) {
    this.check(6);
    this.offset = encoding.writeU48BE(this.data, value, this.offset);
    return this;
  }

  /**
   * Write uint56le.
   * @param {Number} value
   */

  writeU56(value) {
    this.check(7);
    this.offset = encoding.writeU56(this.data, value, this.offset);
    return this;
  }

  /**
   * Write uint56be.
   * @param {Number} value
   */

  writeU56BE(value) {
    this.check(7);
    this.offset = encoding.writeU56BE(this.data, value, this.offset);
    return this;
  }

  /**
   * Write uint64le.
   * @param {Number} value
   */

  writeU64(value) {
    this.check(8);
    this.offset = encoding.writeU64(this.data, value, this.offset);
    return this;
  }

  /**
   * Write uint64be.
   * @param {Number} value
   */

  writeU64BE(value) {
    this.check(8);
    this.offset = encoding.writeU64BE(this.data, value, this.offset);
    return this;
  }

  /**
   * Write int8.
   * @param {Number} value
   */

  writeI8(value) {
    this.check(1);
    this.offset = encoding.writeI8(this.data, value, this.offset);
    return this;
  }

  /**
   * Write int16le.
   * @param {Number} value
   */

  writeI16(value) {
    this.check(2);
    this.offset = encoding.writeI16(this.data, value, this.offset);
    return this;
  }

  /**
   * Write int16be.
   * @param {Number} value
   */

  writeI16BE(value) {
    this.check(2);
    this.offset = encoding.writeI16BE(this.data, value, this.offset);
    return this;
  }

  /**
   * Write int24le.
   * @param {Number} value
   */

  writeI24(value) {
    this.check(3);
    this.offset = encoding.writeI24(this.data, value, this.offset);
    return this;
  }

  /**
   * Write int24be.
   * @param {Number} value
   */

  writeI24BE(value) {
    this.check(3);
    this.offset = encoding.writeI24BE(this.data, value, this.offset);
    return this;
  }

  /**
   * Write int32le.
   * @param {Number} value
   */

  writeI32(value) {
    this.check(4);
    this.offset = encoding.writeI32(this.data, value, this.offset);
    return this;
  }

  /**
   * Write int32be.
   * @param {Number} value
   */

  writeI32BE(value) {
    this.check(4);
    this.offset = encoding.writeI32BE(this.data, value, this.offset);
    return this;
  }

  /**
   * Write int40le.
   * @param {Number} value
   */

  writeI40(value) {
    this.check(5);
    this.offset = encoding.writeI40(this.data, value, this.offset);
    return this;
  }

  /**
   * Write int40be.
   * @param {Number} value
   */

  writeI40BE(value) {
    this.check(5);
    this.offset = encoding.writeI40BE(this.data, value, this.offset);
    return this;
  }

  /**
   * Write int48le.
   * @param {Number} value
   */

  writeI48(value) {
    this.check(6);
    this.offset = encoding.writeI48(this.data, value, this.offset);
    return this;
  }

  /**
   * Write int48be.
   * @param {Number} value
   */

  writeI48BE(value) {
    this.check(6);
    this.offset = encoding.writeI48BE(this.data, value, this.offset);
    return this;
  }

  /**
   * Write int56le.
   * @param {Number} value
   */

  writeI56(value) {
    this.check(7);
    this.offset = encoding.writeI56(this.data, value, this.offset);
    return this;
  }

  /**
   * Write int56be.
   * @param {Number} value
   */

  writeI56BE(value) {
    this.check(7);
    this.offset = encoding.writeI56BE(this.data, value, this.offset);
    return this;
  }

  /**
   * Write int64le.
   * @param {Number} value
   */

  writeI64(value) {
    this.check(8);
    this.offset = encoding.writeI64(this.data, value, this.offset);
    return this;
  }

  /**
   * Write int64be.
   * @param {Number} value
   */

  writeI64BE(value) {
    this.check(8);
    this.offset = encoding.writeI64BE(this.data, value, this.offset);
    return this;
  }

  /**
   * Write float le.
   * @param {Number} value
   */

  writeFloat(value) {
    this.check(4);
    this.offset = encoding.writeFloat(this.data, value, this.offset);
    return this;
  }

  /**
   * Write float be.
   * @param {Number} value
   */

  writeFloatBE(value) {
    this.check(4);
    this.offset = encoding.writeFloatBE(this.data, value, this.offset);
    return this;
  }

  /**
   * Write double le.
   * @param {Number} value
   */

  writeDouble(value) {
    this.check(8);
    this.offset = encoding.writeDouble(this.data, value, this.offset);
    return this;
  }

  /**
   * Write double be.
   * @param {Number} value
   */

  writeDoubleBE(value) {
    this.check(8);
    this.offset = encoding.writeDoubleBE(this.data, value, this.offset);
    return this;
  }

  /**
   * Write a varint.
   * @param {Number} value
   */

  writeVarint(value) {
    this.offset = encoding.writeVarint(this.data, value, this.offset);
    return this;
  }

  /**
   * Write a varint (type 2).
   * @param {Number} value
   */

  writeVarint2(value) {
    this.offset = encoding.writeVarint2(this.data, value, this.offset);
    return this;
  }

  /**
   * Write bytes.
   * @param {Buffer} value
   */

  writeBytes(value) {
    enforce(Buffer.isBuffer(value), 'value', 'buffer');

    this.check(value.length);
    this.offset += value.copy(this.data, this.offset);

    return this;
  }

  /**
   * Write bytes with a varint length before them.
   * @param {Buffer} value
   */

  writeVarBytes(value) {
    enforce(Buffer.isBuffer(value), 'value', 'buffer');

    this.writeVarint(value.length);
    this.writeBytes(value);

    return this;
  }

  /**
   * Copy bytes.
   * @param {Buffer} value
   * @param {Number} start
   * @param {Number} end
   */

  copy(value, start, end) {
    enforce(Buffer.isBuffer(value), 'value', 'buffer');
    enforce((start >>> 0) === start, 'start', 'integer');
    enforce((end >>> 0) === end, 'end', 'integer');
    enforce(end >= start, 'start', 'integer');

    this.check(end - start);
    this.offset += value.copy(this.data, this.offset, start, end);

    return this;
  }

  /**
   * Write string to buffer.
   * @param {String} value
   * @param {String?} enc - Any buffer-supported encoding.
   */

  writeString(value, enc) {
    if (enc == null)
      enc = 'binary';

    enforce(typeof value === 'string', 'value', 'string');
    enforce(typeof enc === 'string', 'enc', 'string');

    if (value.length === 0)
      return this;

    const size = Buffer.byteLength(value, enc);

    this.check(size);

    this.offset += this.data.write(value, this.offset, enc);

    return this;
  }

  /**
   * Write a 32 byte hash.
   * @param {Hash} value
   */

  writeHash(value) {
    if (typeof value !== 'string') {
      enforce(Buffer.isBuffer(value), 'value', 'buffer');
      enforce(value.length === 32, 'value', '32-byte hash');
      this.writeBytes(value);
      return this;
    }

    enforce(value.length === 64, 'value', '32-byte hash');

    this.check(32);
    this.offset += this.data.write(value, this.offset, 'hex');

    return this;
  }

  /**
   * Write a string with a varint length before it.
   * @param {String}
   * @param {String?} enc - Any buffer-supported encoding.
   */

  writeVarString(value, enc) {
    if (enc == null)
      enc = 'binary';

    enforce(typeof value === 'string', 'value', 'string');
    enforce(typeof enc === 'string', 'enc', 'string');

    if (value.length === 0) {
      this.writeVarint(0);
      return this;
    }

    const size = Buffer.byteLength(value, enc);

    this.writeVarint(size);
    this.check(size);
    this.offset += this.data.write(value, this.offset, enc);

    return this;
  }

  /**
   * Write a null-terminated string.
   * @param {String|Buffer}
   * @param {String?} enc - Any buffer-supported encoding.
   */

  writeNullString(value, enc) {
    this.writeString(value, enc);
    this.writeU8(0);
    return this;
  }

  /**
   * Calculate and write a checksum for the data written so far.
   * @param {Function} hash
   */

  writeChecksum(hash) {
    if (!hash || typeof hash.digest !== 'function')
      enforce(typeof hash === 'function', 'hash', 'function');

    this.check(4);

    const data = this.data.slice(0, this.offset);
    const raw = hash.digest ? hash.digest(data) : hash(data);

    raw.copy(this.data, this.offset, 0, 4);

    this.offset += 4;

    return this;
  }

  /**
   * Fill N bytes with value.
   * @param {Number} value
   * @param {Number} size
   */

  fill(value, size) {
    enforce((value & 0xff) === value, 'value', 'byte');
    enforce((size >>> 0) === size, 'size', 'integer');

    this.check(size);

    this.data.fill(value, this.offset, this.offset + size);
    this.offset += size;

    return this;
  }
}

/*
 * Expose
 */

module.exports = StaticWriter;
