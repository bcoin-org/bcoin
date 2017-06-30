/*!
 * reader.js - buffer reader for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const encoding = require('./encoding');
const digest = require('../crypto/digest');

/**
 * An object that allows reading of buffers in a sane manner.
 * @alias module:utils.BufferReader
 * @constructor
 * @param {Buffer} data
 * @param {Boolean?} zeroCopy - Do not reallocate buffers when
 * slicing. Note that this can lead to memory leaks if not used
 * carefully.
 */

function BufferReader(data, zeroCopy) {
  if (!(this instanceof BufferReader))
    return new BufferReader(data, zeroCopy);

  assert(Buffer.isBuffer(data), 'Must pass a Buffer.');

  this.data = data;
  this.offset = 0;
  this.zeroCopy = zeroCopy || false;
  this.stack = [];
}

/**
 * Assertion.
 * @param {Boolean} value
 */

BufferReader.prototype.assert = function assert(value) {
  if (!value)
    throw new encoding.EncodingError(this.offset, 'Out of bounds read');
};

/**
 * Assertion.
 * @param {Boolean} value
 * @param {String} reason
 */

BufferReader.prototype.enforce = function enforce(value, reason) {
  if (!value)
    throw new encoding.EncodingError(this.offset, reason);
};

/**
 * Get total size of passed-in Buffer.
 * @returns {Buffer}
 */

BufferReader.prototype.getSize = function getSize() {
  return this.data.length;
};

/**
 * Calculate number of bytes left to read.
 * @returns {Number}
 */

BufferReader.prototype.left = function left() {
  this.assert(this.offset <= this.data.length);
  return this.data.length - this.offset;
};

/**
 * Seek to a position to read from by offset.
 * @param {Number} off - Offset (positive or negative).
 */

BufferReader.prototype.seek = function seek(off) {
  this.assert(this.offset + off >= 0);
  this.assert(this.offset + off <= this.data.length);
  this.offset += off;
  return off;
};

/**
 * Mark the current starting position.
 */

BufferReader.prototype.start = function start() {
  this.stack.push(this.offset);
  return this.offset;
};

/**
 * Stop reading. Pop the start position off the stack
 * and calculate the size of the data read.
 * @returns {Number} Size.
 * @throws on empty stack.
 */

BufferReader.prototype.end = function _end() {
  let start, end;

  assert(this.stack.length > 0);

  start = this.stack.pop();
  end = this.offset;

  return end - start;
};

/**
 * Stop reading. Pop the start position off the stack
 * and return the data read.
 * @param {Bolean?} zeroCopy - Do a fast buffer
 * slice instead of allocating a new buffer (warning:
 * may cause memory leaks if not used with care).
 * @returns {Buffer} Data read.
 * @throws on empty stack.
 */

BufferReader.prototype.endData = function endData(zeroCopy) {
  let ret, start, end, size, data;

  assert(this.stack.length > 0);

  start = this.stack.pop();
  end = this.offset;
  size = end - start;
  data = this.data;

  if (size === data.length)
    return data;

  if (this.zeroCopy || zeroCopy)
    return data.slice(start, end);

  ret = Buffer.allocUnsafe(size);
  data.copy(ret, 0, start, end);

  return ret;
};

/**
 * Destroy the reader. Remove references to the data.
 */

BufferReader.prototype.destroy = function destroy() {
  this.offset = null;
  this.stack = null;
  this.data = null;
};

/**
 * Read uint8.
 * @returns {Number}
 */

BufferReader.prototype.readU8 = function readU8() {
  let ret;
  this.assert(this.offset + 1 <= this.data.length);
  ret = this.data[this.offset];
  this.offset += 1;
  return ret;
};

/**
 * Read uint16le.
 * @returns {Number}
 */

BufferReader.prototype.readU16 = function readU16() {
  let ret;
  this.assert(this.offset + 2 <= this.data.length);
  ret = this.data.readUInt16LE(this.offset, true);
  this.offset += 2;
  return ret;
};

/**
 * Read uint16be.
 * @returns {Number}
 */

BufferReader.prototype.readU16BE = function readU16BE() {
  let ret;
  this.assert(this.offset + 2 <= this.data.length);
  ret = this.data.readUInt16BE(this.offset, true);
  this.offset += 2;
  return ret;
};

/**
 * Read uint32le.
 * @returns {Number}
 */

BufferReader.prototype.readU32 = function readU32() {
  let ret;
  this.assert(this.offset + 4 <= this.data.length);
  ret = this.data.readUInt32LE(this.offset, true);
  this.offset += 4;
  return ret;
};

/**
 * Read uint32be.
 * @returns {Number}
 */

BufferReader.prototype.readU32BE = function readU32BE() {
  let ret;
  this.assert(this.offset + 4 <= this.data.length);
  ret = this.data.readUInt32BE(this.offset, true);
  this.offset += 4;
  return ret;
};

/**
 * Read uint64le as a js number.
 * @returns {Number}
 * @throws on num > MAX_SAFE_INTEGER
 */

BufferReader.prototype.readU64 = function readU64() {
  let ret;
  this.assert(this.offset + 8 <= this.data.length);
  ret = encoding.readU64(this.data, this.offset);
  this.offset += 8;
  return ret;
};

/**
 * Read uint64be as a js number.
 * @returns {Number}
 * @throws on num > MAX_SAFE_INTEGER
 */

BufferReader.prototype.readU64BE = function readU64BE() {
  let ret;
  this.assert(this.offset + 8 <= this.data.length);
  ret = encoding.readU64BE(this.data, this.offset);
  this.offset += 8;
  return ret;
};

/**
 * Read first least significant 53 bits of
 * a uint64le as a js number. Maintain the sign.
 * @returns {Number}
 */

BufferReader.prototype.readU53 = function readU53() {
  let ret;
  this.assert(this.offset + 8 <= this.data.length);
  ret = encoding.readU53(this.data, this.offset);
  this.offset += 8;
  return ret;
};

/**
 * Read first least significant 53 bits of
 * a uint64be as a js number. Maintain the sign.
 * @returns {Number}
 */

BufferReader.prototype.readU53BE = function readU53BE() {
  let ret;
  this.assert(this.offset + 8 <= this.data.length);
  ret = encoding.readU53BE(this.data, this.offset);
  this.offset += 8;
  return ret;
};

/**
 * Read int8.
 * @returns {Number}
 */

BufferReader.prototype.read8 = function read8() {
  let ret;
  this.assert(this.offset + 1 <= this.data.length);
  ret = this.data.readInt8(this.offset, true);
  this.offset += 1;
  return ret;
};

/**
 * Read int16le.
 * @returns {Number}
 */

BufferReader.prototype.read16 = function read16() {
  let ret;
  this.assert(this.offset + 2 <= this.data.length);
  ret = this.data.readInt16LE(this.offset, true);
  this.offset += 2;
  return ret;
};

/**
 * Read int16be.
 * @returns {Number}
 */

BufferReader.prototype.read16BE = function read16BE() {
  let ret;
  this.assert(this.offset + 2 <= this.data.length);
  ret = this.data.readInt16BE(this.offset, true);
  this.offset += 2;
  return ret;
};

/**
 * Read int32le.
 * @returns {Number}
 */

BufferReader.prototype.read32 = function read32() {
  let ret;
  this.assert(this.offset + 4 <= this.data.length);
  ret = this.data.readInt32LE(this.offset, true);
  this.offset += 4;
  return ret;
};

/**
 * Read int32be.
 * @returns {Number}
 */

BufferReader.prototype.read32BE = function read32BE() {
  let ret;
  this.assert(this.offset + 4 <= this.data.length);
  ret = this.data.readInt32BE(this.offset, true);
  this.offset += 4;
  return ret;
};

/**
 * Read int64le as a js number.
 * @returns {Number}
 * @throws on num > MAX_SAFE_INTEGER
 */

BufferReader.prototype.read64 = function read64() {
  let ret;
  this.assert(this.offset + 8 <= this.data.length);
  ret = encoding.read64(this.data, this.offset);
  this.offset += 8;
  return ret;
};

/**
 * Read int64be as a js number.
 * @returns {Number}
 * @throws on num > MAX_SAFE_INTEGER
 */

BufferReader.prototype.read64BE = function read64BE() {
  let ret;
  this.assert(this.offset + 8 <= this.data.length);
  ret = encoding.read64BE(this.data, this.offset);
  this.offset += 8;
  return ret;
};

/**
 * Read first least significant 53 bits of
 * a int64le as a js number. Maintain the sign.
 * @returns {Number}
 */

BufferReader.prototype.read53 = function read53() {
  let ret;
  this.assert(this.offset + 8 <= this.data.length);
  ret = encoding.read53(this.data, this.offset);
  this.offset += 8;
  return ret;
};

/**
 * Read first least significant 53 bits of
 * a int64be as a js number. Maintain the sign.
 * @returns {Number}
 */

BufferReader.prototype.read53BE = function read53BE() {
  let ret;
  this.assert(this.offset + 8 <= this.data.length);
  ret = encoding.read53BE(this.data, this.offset);
  this.offset += 8;
  return ret;
};

/**
 * Read uint64le.
 * @returns {BN}
 */

BufferReader.prototype.readU64BN = function readU64BN() {
  let ret;
  this.assert(this.offset + 8 <= this.data.length);
  ret = encoding.readU64BN(this.data, this.offset);
  this.offset += 8;
  return ret;
};

/**
 * Read uint64be.
 * @returns {BN}
 */

BufferReader.prototype.readU64BEBN = function readU64BEBN() {
  let ret;
  this.assert(this.offset + 8 <= this.data.length);
  ret = encoding.readU64BEBN(this.data, this.offset);
  this.offset += 8;
  return ret;
};

/**
 * Read int64le.
 * @returns {BN}
 */

BufferReader.prototype.read64BN = function read64BN() {
  let ret;
  this.assert(this.offset + 8 <= this.data.length);
  ret = encoding.read64BN(this.data, this.offset);
  this.offset += 8;
  return ret;
};

/**
 * Read int64be.
 * @returns {BN}
 */

BufferReader.prototype.read64BEBN = function read64BEBN() {
  let ret;
  this.assert(this.offset + 8 <= this.data.length);
  ret = encoding.read64BEBN(this.data, this.offset);
  this.offset += 8;
  return ret;
};

/**
 * Read float le.
 * @returns {Number}
 */

BufferReader.prototype.readFloat = function readFloat() {
  let ret;
  this.assert(this.offset + 4 <= this.data.length);
  ret = this.data.readFloatLE(this.offset, true);
  this.offset += 4;
  return ret;
};

/**
 * Read float be.
 * @returns {Number}
 */

BufferReader.prototype.readFloatBE = function readFloatBE() {
  let ret;
  this.assert(this.offset + 4 <= this.data.length);
  ret = this.data.readFloatBE(this.offset, true);
  this.offset += 4;
  return ret;
};

/**
 * Read double float le.
 * @returns {Number}
 */

BufferReader.prototype.readDouble = function readDouble() {
  let ret;
  this.assert(this.offset + 8 <= this.data.length);
  ret = this.data.readDoubleLE(this.offset, true);
  this.offset += 8;
  return ret;
};

/**
 * Read double float be.
 * @returns {Number}
 */

BufferReader.prototype.readDoubleBE = function readDoubleBE() {
  let ret;
  this.assert(this.offset + 8 <= this.data.length);
  ret = this.data.readDoubleBE(this.offset, true);
  this.offset += 8;
  return ret;
};

/**
 * Read a varint.
 * @returns {Number}
 */

BufferReader.prototype.readVarint = function readVarint() {
  let {size, value} = encoding.readVarint(this.data, this.offset);
  this.offset += size;
  return value;
};

/**
 * Skip past a varint.
 * @returns {Number}
 */

BufferReader.prototype.skipVarint = function skipVarint() {
  let size = encoding.skipVarint(this.data, this.offset);
  this.assert(this.offset + size <= this.data.length);
  this.offset += size;
};

/**
 * Read a varint.
 * @returns {BN}
 */

BufferReader.prototype.readVarintBN = function readVarintBN() {
  let {size, value} = encoding.readVarintBN(this.data, this.offset);
  this.offset += size;
  return value;
};

/**
 * Read a varint (type 2).
 * @returns {Number}
 */

BufferReader.prototype.readVarint2 = function readVarint2() {
  let {size, value} = encoding.readVarint2(this.data, this.offset);
  this.offset += size;
  return value;
};

/**
 * Skip past a varint (type 2).
 * @returns {Number}
 */

BufferReader.prototype.skipVarint2 = function skipVarint2() {
  let size = encoding.skipVarint2(this.data, this.offset);
  this.assert(this.offset + size <= this.data.length);
  this.offset += size;
};

/**
 * Read a varint (type 2).
 * @returns {BN}
 */

BufferReader.prototype.readVarint2BN = function readVarint2BN() {
  let {size, value} = encoding.readVarint2BN(this.data, this.offset);
  this.offset += size;
  return value;
};

/**
 * Read N bytes (will do a fast slice if zero copy).
 * @param {Number} size
 * @param {Bolean?} zeroCopy - Do a fast buffer
 * slice instead of allocating a new buffer (warning:
 * may cause memory leaks if not used with care).
 * @returns {Buffer}
 */

BufferReader.prototype.readBytes = function readBytes(size, zeroCopy) {
  let ret;

  assert(size >= 0);
  this.assert(this.offset + size <= this.data.length);

  if (this.zeroCopy || zeroCopy) {
    ret = this.data.slice(this.offset, this.offset + size);
  } else {
    ret = Buffer.allocUnsafe(size);
    this.data.copy(ret, 0, this.offset, this.offset + size);
  }

  this.offset += size;

  return ret;
};

/**
 * Read a varint number of bytes (will do a fast slice if zero copy).
 * @param {Bolean?} zeroCopy - Do a fast buffer
 * slice instead of allocating a new buffer (warning:
 * may cause memory leaks if not used with care).
 * @returns {Buffer}
 */

BufferReader.prototype.readVarBytes = function readVarBytes(zeroCopy) {
  return this.readBytes(this.readVarint(), zeroCopy);
};

/**
 * Read a string.
 * @param {String} enc - Any buffer-supported encoding.
 * @param {Number} size
 * @returns {String}
 */

BufferReader.prototype.readString = function readString(enc, size) {
  let ret;
  assert(size >= 0);
  this.assert(this.offset + size <= this.data.length);
  ret = this.data.toString(enc, this.offset, this.offset + size);
  this.offset += size;
  return ret;
};

/**
 * Read a 32-byte hash.
 * @param {String} enc - `"hex"` or `null`.
 * @returns {Hash|Buffer}
 */

BufferReader.prototype.readHash = function readHash(enc) {
  if (enc)
    return this.readString(enc, 32);
  return this.readBytes(32);
};

/**
 * Read string of a varint length.
 * @param {String} enc - Any buffer-supported encoding.
 * @param {Number?} limit - Size limit.
 * @returns {String}
 */

BufferReader.prototype.readVarString = function readVarString(enc, limit) {
  let size = this.readVarint();
  this.enforce(!limit || size <= limit, 'String exceeds limit.');
  return this.readString(enc, size);
};

/**
 * Read a null-terminated string.
 * @param {String} enc - Any buffer-supported encoding.
 * @returns {String}
 */

BufferReader.prototype.readNullString = function readNullString(enc) {
  let i, ret;
  this.assert(this.offset + 1 <= this.data.length);
  for (i = this.offset; i < this.data.length; i++) {
    if (this.data[i] === 0)
      break;
  }
  this.assert(i !== this.data.length);
  ret = this.readString(enc, i - this.offset);
  this.offset = i + 1;
  return ret;
};

/**
 * Create a checksum from the last start position.
 * @returns {Number} Checksum.
 */

BufferReader.prototype.createChecksum = function createChecksum() {
  let start = 0;
  let data;

  if (this.stack.length > 0)
    start = this.stack[this.stack.length - 1];

  data = this.data.slice(start, this.offset);

  return digest.hash256(data).readUInt32LE(0, true);
};

/**
 * Verify a 4-byte checksum against a calculated checksum.
 * @returns {Number} checksum
 * @throws on bad checksum
 */

BufferReader.prototype.verifyChecksum = function verifyChecksum() {
  let chk = this.createChecksum();
  let checksum = this.readU32();
  this.enforce(chk === checksum, 'Checksum mismatch.');
  return checksum;
};

/*
 * Expose
 */

module.exports = BufferReader;
