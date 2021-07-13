/*!
 * reader.js - buffer reader for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
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

/**
 * Buffer Reader
 */

class BufferReader {
  /**
   * Create a buffer reader.
   * @constructor
   * @param {Buffer} data
   * @param {Boolean?} zeroCopy - Do not reallocate buffers when
   * slicing. Note that this can lead to memory leaks if not used
   * carefully.
   */

  constructor(data, zeroCopy = false) {
    enforce(Buffer.isBuffer(data), 'data', 'buffer');
    enforce(typeof zeroCopy === 'boolean', 'zeroCopy', 'boolean');

    this.data = data;
    this.offset = 0;
    this.zeroCopy = zeroCopy;
    this.stack = [];
  }

  /**
   * Assertion.
   * @param {Number} size
   */

  check(size) {
    if (this.offset + size > this.data.length)
      throw new EncodingError(this.offset, 'Out of bounds read', this.check);
  }

  /**
   * Get total size of passed-in Buffer.
   * @returns {Buffer}
   */

  getSize() {
    return this.data.length;
  }

  /**
   * Calculate number of bytes left to read.
   * @returns {Number}
   */

  left() {
    this.check(0);
    return this.data.length - this.offset;
  }

  /**
   * Seek to a position to read from by offset.
   * @param {Number} off - Offset (positive or negative).
   */

  seek(off) {
    enforce(Number.isSafeInteger(off), 'off', 'integer');

    if (this.offset + off < 0)
      throw new EncodingError(this.offset, 'Out of bounds read');

    this.check(off);
    this.offset += off;

    return this;
  }

  /**
   * Mark the current starting position.
   */

  start() {
    this.stack.push(this.offset);
    return this.offset;
  }

  /**
   * Stop reading. Pop the start position off the stack
   * and calculate the size of the data read.
   * @returns {Number} Size.
   * @throws on empty stack.
   */

  end() {
    if (this.stack.length === 0)
      throw new Error('Cannot end without a stack item.');

    const start = this.stack.pop();

    return this.offset - start;
  }

  /**
   * Stop reading. Pop the start position off the stack
   * and return the data read.
   * @param {Bolean?} zeroCopy - Do a fast buffer
   * slice instead of allocating a new buffer (warning:
   * may cause memory leaks if not used with care).
   * @returns {Buffer} Data read.
   * @throws on empty stack.
   */

  endData(zeroCopy = false) {
    enforce(typeof zeroCopy === 'boolean', 'zeroCopy', 'boolean');

    if (this.stack.length === 0)
      throw new Error('Cannot end without a stack item.');

    const start = this.stack.pop();
    const end = this.offset;
    const size = end - start;
    const data = this.data;

    if (size === data.length)
      return data;

    if (this.zeroCopy || zeroCopy)
      return data.slice(start, end);

    const ret = Buffer.allocUnsafeSlow(size);

    data.copy(ret, 0, start, end);

    return ret;
  }

  /**
   * Destroy the reader. Remove references to the data.
   */

  destroy() {
    this.data = EMPTY;
    this.offset = 0;
    this.stack.length = 0;
    return this;
  }

  /**
   * Read uint8.
   * @returns {Number}
   */

  readU8() {
    this.check(1);

    const ret = this.data[this.offset];

    this.offset += 1;

    return ret;
  }

  /**
   * Read uint16le.
   * @returns {Number}
   */

  readU16() {
    this.check(2);

    const ret = encoding.readU16(this.data, this.offset);

    this.offset += 2;

    return ret;
  }

  /**
   * Read uint16be.
   * @returns {Number}
   */

  readU16BE() {
    this.check(2);

    const ret = encoding.readU16BE(this.data, this.offset);

    this.offset += 2;

    return ret;
  }

  /**
   * Read uint24le.
   * @returns {Number}
   */

  readU24() {
    this.check(3);

    const ret = encoding.readU24(this.data, this.offset);

    this.offset += 3;

    return ret;
  }

  /**
   * Read uint24be.
   * @returns {Number}
   */

  readU24BE() {
    this.check(3);

    const ret = encoding.readU24BE(this.data, this.offset);

    this.offset += 3;

    return ret;
  }

  /**
   * Read uint32le.
   * @returns {Number}
   */

  readU32() {
    this.check(4);

    const ret = encoding.readU32(this.data, this.offset);

    this.offset += 4;

    return ret;
  }

  /**
   * Read uint32be.
   * @returns {Number}
   */

  readU32BE() {
    this.check(4);

    const ret = encoding.readU32BE(this.data, this.offset);

    this.offset += 4;

    return ret;
  }

  /**
   * Read uint40le.
   * @returns {Number}
   */

  readU40() {
    this.check(5);

    const ret = encoding.readU40(this.data, this.offset);

    this.offset += 5;

    return ret;
  }

  /**
   * Read uint40be.
   * @returns {Number}
   */

  readU40BE() {
    this.check(5);

    const ret = encoding.readU40BE(this.data, this.offset);

    this.offset += 5;

    return ret;
  }

  /**
   * Read uint48le.
   * @returns {Number}
   */

  readU48() {
    this.check(6);

    const ret = encoding.readU48(this.data, this.offset);

    this.offset += 6;

    return ret;
  }

  /**
   * Read uint48be.
   * @returns {Number}
   */

  readU48BE() {
    this.check(6);

    const ret = encoding.readU48BE(this.data, this.offset);

    this.offset += 6;

    return ret;
  }

  /**
   * Read uint56le.
   * @returns {Number}
   */

  readU56() {
    this.check(7);

    const ret = encoding.readU56(this.data, this.offset);

    this.offset += 7;

    return ret;
  }

  /**
   * Read uint56be.
   * @returns {Number}
   */

  readU56BE() {
    this.check(7);

    const ret = encoding.readU56BE(this.data, this.offset);

    this.offset += 7;

    return ret;
  }

  /**
   * Read uint64le as a js number.
   * @returns {Number}
   * @throws on num > MAX_SAFE_INTEGER
   */

  readU64() {
    this.check(8);

    const ret = encoding.readU64(this.data, this.offset);

    this.offset += 8;

    return ret;
  }

  /**
   * Read uint64be as a js number.
   * @returns {Number}
   * @throws on num > MAX_SAFE_INTEGER
   */

  readU64BE() {
    this.check(8);

    const ret = encoding.readU64BE(this.data, this.offset);

    this.offset += 8;

    return ret;
  }

  /**
   * Read int8.
   * @returns {Number}
   */

  readI8() {
    this.check(1);

    const ret = encoding.readI8(this.data, this.offset);

    this.offset += 1;

    return ret;
  }

  /**
   * Read int16le.
   * @returns {Number}
   */

  readI16() {
    this.check(2);

    const ret = encoding.readI16(this.data, this.offset);

    this.offset += 2;

    return ret;
  }

  /**
   * Read int16be.
   * @returns {Number}
   */

  readI16BE() {
    this.check(2);

    const ret = encoding.readI16BE(this.data, this.offset);

    this.offset += 2;

    return ret;
  }

  /**
   * Read int24le.
   * @returns {Number}
   */

  readI24() {
    this.check(3);

    const ret = encoding.readI24(this.data, this.offset);

    this.offset += 3;

    return ret;
  }

  /**
   * Read int24be.
   * @returns {Number}
   */

  readI24BE() {
    this.check(3);

    const ret = encoding.readI24BE(this.data, this.offset);

    this.offset += 3;

    return ret;
  }

  /**
   * Read int32le.
   * @returns {Number}
   */

  readI32() {
    this.check(4);

    const ret = encoding.readI32(this.data, this.offset);

    this.offset += 4;

    return ret;
  }

  /**
   * Read int32be.
   * @returns {Number}
   */

  readI32BE() {
    this.check(4);

    const ret = encoding.readI32BE(this.data, this.offset);

    this.offset += 4;

    return ret;
  }

  /**
   * Read int40le.
   * @returns {Number}
   */

  readI40() {
    this.check(5);

    const ret = encoding.readI40(this.data, this.offset);

    this.offset += 5;

    return ret;
  }

  /**
   * Read int40be.
   * @returns {Number}
   */

  readI40BE() {
    this.check(5);

    const ret = encoding.readI40BE(this.data, this.offset);

    this.offset += 5;

    return ret;
  }

  /**
   * Read int48le.
   * @returns {Number}
   */

  readI48() {
    this.check(6);

    const ret = encoding.readI48(this.data, this.offset);

    this.offset += 6;

    return ret;
  }

  /**
   * Read int48be.
   * @returns {Number}
   */

  readI48BE() {
    this.check(6);

    const ret = encoding.readI48BE(this.data, this.offset);

    this.offset += 6;

    return ret;
  }

  /**
   * Read int56le.
   * @returns {Number}
   */

  readI56() {
    this.check(7);

    const ret = encoding.readI56(this.data, this.offset);

    this.offset += 7;

    return ret;
  }

  /**
   * Read int56be.
   * @returns {Number}
   */

  readI56BE() {
    this.check(7);

    const ret = encoding.readI56BE(this.data, this.offset);

    this.offset += 7;

    return ret;
  }

  /**
   * Read int64le as a js number.
   * @returns {Number}
   * @throws on num > MAX_SAFE_INTEGER
   */

  readI64() {
    this.check(8);

    const ret = encoding.readI64(this.data, this.offset);

    this.offset += 8;

    return ret;
  }

  /**
   * Read int64be as a js number.
   * @returns {Number}
   * @throws on num > MAX_SAFE_INTEGER
   */

  readI64BE() {
    this.check(8);

    const ret = encoding.readI64BE(this.data, this.offset);

    this.offset += 8;

    return ret;
  }

  /**
   * Read float le.
   * @returns {Number}
   */

  readFloat() {
    this.check(4);

    const ret = encoding.readFloat(this.data, this.offset);

    this.offset += 4;

    return ret;
  }

  /**
   * Read float be.
   * @returns {Number}
   */

  readFloatBE() {
    this.check(4);

    const ret = encoding.readFloatBE(this.data, this.offset);

    this.offset += 4;

    return ret;
  }

  /**
   * Read double float le.
   * @returns {Number}
   */

  readDouble() {
    this.check(8);

    const ret = encoding.readDouble(this.data, this.offset);

    this.offset += 8;

    return ret;
  }

  /**
   * Read double float be.
   * @returns {Number}
   */

  readDoubleBE() {
    this.check(8);

    const ret = encoding.readDoubleBE(this.data, this.offset);

    this.offset += 8;

    return ret;
  }

  /**
   * Read a varint.
   * @returns {Number}
   */

  readVarint() {
    const {size, value} = encoding.readVarint(this.data, this.offset);

    this.offset += size;

    return value;
  }

  /**
   * Read a varint (type 2).
   * @returns {Number}
   */

  readVarint2() {
    const {size, value} = encoding.readVarint2(this.data, this.offset);

    this.offset += size;

    return value;
  }

  /**
   * Read N bytes (will do a fast slice if zero copy).
   * @param {Number} size
   * @param {Bolean?} zeroCopy - Do a fast buffer
   * slice instead of allocating a new buffer (warning:
   * may cause memory leaks if not used with care).
   * @returns {Buffer}
   */

  readBytes(size, zeroCopy = false) {
    enforce((size >>> 0) === size, 'size', 'integer');
    enforce(typeof zeroCopy === 'boolean', 'zeroCopy', 'boolean');

    this.check(size);

    let ret;

    if (this.zeroCopy || zeroCopy) {
      ret = this.data.slice(this.offset, this.offset + size);
    } else {
      ret = Buffer.allocUnsafeSlow(size);
      this.data.copy(ret, 0, this.offset, this.offset + size);
    }

    this.offset += size;

    return ret;
  }

  /**
   * Read a varint number of bytes (will do a fast slice if zero copy).
   * @param {Bolean?} zeroCopy - Do a fast buffer
   * slice instead of allocating a new buffer (warning:
   * may cause memory leaks if not used with care).
   * @returns {Buffer}
   */

  readVarBytes(zeroCopy = false) {
    return this.readBytes(this.readVarint(), zeroCopy);
  }

  /**
   * Slice N bytes and create a child reader.
   * @param {Number} size
   * @returns {BufferReader}
   */

  readChild(size) {
    enforce((size >>> 0) === size, 'size', 'integer');

    this.check(size);

    const data = this.data.slice(0, this.offset + size);
    const br = new this.constructor(data);

    br.offset = this.offset;

    this.offset += size;

    return br;
  }

  /**
   * Read a string.
   * @param {Number} size
   * @param {String} enc - Any buffer-supported encoding.
   * @returns {String}
   */

  readString(size, enc) {
    if (enc == null)
      enc = 'binary';

    enforce((size >>> 0) === size, 'size', 'integer');
    enforce(typeof enc === 'string', 'enc', 'string');

    this.check(size);

    const ret = this.data.toString(enc, this.offset, this.offset + size);

    this.offset += size;

    return ret;
  }

  /**
   * Read a 32-byte hash.
   * @param {String} enc - `"hex"` or `null`.
   * @returns {Hash|Buffer}
   */

  readHash(enc) {
    if (enc)
      return this.readString(32, enc);
    return this.readBytes(32);
  }

  /**
   * Read string of a varint length.
   * @param {String} enc - Any buffer-supported encoding.
   * @param {Number?} limit - Size limit.
   * @returns {String}
   */

  readVarString(enc, limit = 0) {
    if (enc == null)
      enc = 'binary';

    enforce(typeof enc === 'string', 'enc', 'string');
    enforce((limit >>> 0) === limit, 'limit', 'integer');

    const size = this.readVarint();

    if (limit !== 0 && size > limit)
      throw new EncodingError(this.offset, 'String exceeds limit');

    return this.readString(size, enc);
  }

  /**
   * Read a null-terminated string.
   * @param {String} enc - Any buffer-supported encoding.
   * @returns {String}
   */

  readNullString(enc) {
    if (enc == null)
      enc = 'binary';

    enforce(typeof enc === 'string', 'enc', 'string');

    let i = this.offset;

    for (; i < this.data.length; i++) {
      if (this.data[i] === 0)
        break;
    }

    if (i === this.data.length)
      throw new EncodingError(this.offset, 'No NUL terminator');

    const ret = this.readString(i - this.offset, enc);

    this.offset = i + 1;

    return ret;
  }

  /**
   * Create a checksum from the last start position.
   * @param {Function} hash
   * @returns {Number} Checksum.
   */

  createChecksum(hash) {
    if (!hash || typeof hash.digest !== 'function')
      enforce(typeof hash === 'function', 'hash', 'function');

    let start = 0;

    if (this.stack.length > 0)
      start = this.stack[this.stack.length - 1];

    const data = this.data.slice(start, this.offset);
    const raw = hash.digest ? hash.digest(data) : hash(data);

    return encoding.readU32(raw, 0);
  }

  /**
   * Verify a 4-byte checksum against a calculated checksum.
   * @param {Function} hash
   * @returns {Number} checksum
   * @throws on bad checksum
   */

  verifyChecksum(hash) {
    const checksum = this.createChecksum(hash);
    const expect = this.readU32();

    if (checksum !== expect)
      throw new EncodingError(this.offset, 'Checksum mismatch');

    return checksum;
  }
}

/*
 * Expose
 */

module.exports = BufferReader;
