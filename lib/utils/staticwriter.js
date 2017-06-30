/*!
 * staticwriter.js - buffer writer for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const encoding = require('./encoding');
const digest = require('../crypto/digest');

/**
 * Statically allocated buffer writer.
 * @alias module:utils.StaticWriter
 * @constructor
 * @param {Number} size
 */

function StaticWriter(size) {
  if (!(this instanceof StaticWriter))
    return new StaticWriter(size);

  this.data = Buffer.allocUnsafe(size);
  this.written = 0;
}

/**
 * Allocate and render the final buffer.
 * @param {Boolean?} keep - Do not destroy the writer.
 * @returns {Buffer} Rendered buffer.
 */

StaticWriter.prototype.render = function render(keep) {
  let data = this.data;

  assert(this.written === data.length);

  if (!keep)
    this.destroy();

  return data;
};

/**
 * Get size of data written so far.
 * @returns {Number}
 */

StaticWriter.prototype.getSize = function getSize() {
  return this.written;
};

/**
 * Seek to relative offset.
 * @param {Number} offset
 */

StaticWriter.prototype.seek = function seek(offset) {
  this.written += offset;
};

/**
 * Destroy the buffer writer.
 */

StaticWriter.prototype.destroy = function destroy() {
  this.data = null;
  this.written = null;
};

/**
 * Write uint8.
 * @param {Number} value
 */

StaticWriter.prototype.writeU8 = function writeU8(value) {
  this.written = this.data.writeUInt8(value, this.written, true);
};

/**
 * Write uint16le.
 * @param {Number} value
 */

StaticWriter.prototype.writeU16 = function writeU16(value) {
  this.written = this.data.writeUInt16LE(value, this.written, true);
};

/**
 * Write uint16be.
 * @param {Number} value
 */

StaticWriter.prototype.writeU16BE = function writeU16BE(value) {
  this.written = this.data.writeUInt16BE(value, this.written, true);
};

/**
 * Write uint32le.
 * @param {Number} value
 */

StaticWriter.prototype.writeU32 = function writeU32(value) {
  this.written = this.data.writeUInt32LE(value, this.written, true);
};

/**
 * Write uint32be.
 * @param {Number} value
 */

StaticWriter.prototype.writeU32BE = function writeU32BE(value) {
  this.written = this.data.writeUInt32BE(value, this.written, true);
};

/**
 * Write uint64le.
 * @param {Number} value
 */

StaticWriter.prototype.writeU64 = function writeU64(value) {
  this.written = encoding.writeU64(this.data, value, this.written);
};

/**
 * Write uint64be.
 * @param {Number} value
 */

StaticWriter.prototype.writeU64BE = function writeU64BE(value) {
  this.written = encoding.writeU64BE(this.data, value, this.written);
};

/**
 * Write uint64le.
 * @param {BN} value
 */

StaticWriter.prototype.writeU64BN = function writeU64BN(value) {
  assert(false, 'Not implemented.');
};

/**
 * Write uint64be.
 * @param {BN} value
 */

StaticWriter.prototype.writeU64BEBN = function writeU64BEBN(value) {
  assert(false, 'Not implemented.');
};

/**
 * Write int8.
 * @param {Number} value
 */

StaticWriter.prototype.write8 = function write8(value) {
  this.written = this.data.writeInt8(value, this.written, true);
};

/**
 * Write int16le.
 * @param {Number} value
 */

StaticWriter.prototype.write16 = function write16(value) {
  this.written = this.data.writeInt16LE(value, this.written, true);
};

/**
 * Write int16be.
 * @param {Number} value
 */

StaticWriter.prototype.write16BE = function write16BE(value) {
  this.written = this.data.writeInt16BE(value, this.written, true);
};

/**
 * Write int32le.
 * @param {Number} value
 */

StaticWriter.prototype.write32 = function write32(value) {
  this.written = this.data.writeInt32LE(value, this.written, true);
};

/**
 * Write int32be.
 * @param {Number} value
 */

StaticWriter.prototype.write32BE = function write32BE(value) {
  this.written = this.data.writeInt32BE(value, this.written, true);
};

/**
 * Write int64le.
 * @param {Number} value
 */

StaticWriter.prototype.write64 = function write64(value) {
  this.written = encoding.write64(this.data, value, this.written);
};

/**
 * Write int64be.
 * @param {Number} value
 */

StaticWriter.prototype.write64BE = function write64BE(value) {
  this.written = encoding.write64BE(this.data, value, this.written);
};

/**
 * Write int64le.
 * @param {BN} value
 */

StaticWriter.prototype.write64BN = function write64BN(value) {
  assert(false, 'Not implemented.');
};

/**
 * Write int64be.
 * @param {BN} value
 */

StaticWriter.prototype.write64BEBN = function write64BEBN(value) {
  assert(false, 'Not implemented.');
};

/**
 * Write float le.
 * @param {Number} value
 */

StaticWriter.prototype.writeFloat = function writeFloat(value) {
  this.written = this.data.writeFloatLE(value, this.written, true);
};

/**
 * Write float be.
 * @param {Number} value
 */

StaticWriter.prototype.writeFloatBE = function writeFloatBE(value) {
  this.written = this.data.writeFloatBE(value, this.written, true);
};

/**
 * Write double le.
 * @param {Number} value
 */

StaticWriter.prototype.writeDouble = function writeDouble(value) {
  this.written = this.data.writeDoubleLE(value, this.written, true);
};

/**
 * Write double be.
 * @param {Number} value
 */

StaticWriter.prototype.writeDoubleBE = function writeDoubleBE(value) {
  this.written = this.data.writeDoubleBE(value, this.written, true);
};

/**
 * Write a varint.
 * @param {Number} value
 */

StaticWriter.prototype.writeVarint = function writeVarint(value) {
  this.written = encoding.writeVarint(this.data, value, this.written);
};

/**
 * Write a varint.
 * @param {BN} value
 */

StaticWriter.prototype.writeVarintBN = function writeVarintBN(value) {
  assert(false, 'Not implemented.');
};

/**
 * Write a varint (type 2).
 * @param {Number} value
 */

StaticWriter.prototype.writeVarint2 = function writeVarint2(value) {
  this.written = encoding.writeVarint2(this.data, value, this.written);
};

/**
 * Write a varint (type 2).
 * @param {BN} value
 */

StaticWriter.prototype.writeVarint2BN = function writeVarint2BN(value) {
  assert(false, 'Not implemented.');
};

/**
 * Write bytes.
 * @param {Buffer} value
 */

StaticWriter.prototype.writeBytes = function writeBytes(value) {
  if (value.length === 0)
    return;

  value.copy(this.data, this.written);

  this.written += value.length;
};

/**
 * Write bytes with a varint length before them.
 * @param {Buffer} value
 */

StaticWriter.prototype.writeVarBytes = function writeVarBytes(value) {
  this.writeVarint(value.length);
  this.writeBytes(value);
};

/**
 * Copy bytes.
 * @param {Buffer} value
 * @param {Number} start
 * @param {Number} end
 */

StaticWriter.prototype.copy = function copy(value, start, end) {
  let len = end - start;

  if (len === 0)
    return;

  value.copy(this.data, this.written, start, end);
  this.written += len;
};

/**
 * Write string to buffer.
 * @param {String} value
 * @param {String?} enc - Any buffer-supported encoding.
 */

StaticWriter.prototype.writeString = function writeString(value, enc) {
  let size;

  if (value.length === 0)
    return;

  size = Buffer.byteLength(value, enc);

  this.data.write(value, this.written, enc);

  this.written += size;
};

/**
 * Write a 32 byte hash.
 * @param {Hash} value
 */

StaticWriter.prototype.writeHash = function writeHash(value) {
  if (typeof value !== 'string') {
    assert(value.length === 32);
    return this.writeBytes(value);
  }
  assert(value.length === 64);
  this.data.write(value, this.written, 'hex');
  this.written += 32;
};

/**
 * Write a string with a varint length before it.
 * @param {String}
 * @param {String?} enc - Any buffer-supported encoding.
 */

StaticWriter.prototype.writeVarString = function writeVarString(value, enc) {
  let size;

  if (value.length === 0) {
    this.writeVarint(0);
    return;
  }

  size = Buffer.byteLength(value, enc);

  this.writeVarint(size);
  this.data.write(value, this.written, enc);

  this.written += size;
};

/**
 * Write a null-terminated string.
 * @param {String|Buffer}
 * @param {String?} enc - Any buffer-supported encoding.
 */

StaticWriter.prototype.writeNullString = function writeNullString(value, enc) {
  this.writeString(value, enc);
  this.writeU8(0);
};

/**
 * Calculate and write a checksum for the data written so far.
 */

StaticWriter.prototype.writeChecksum = function writeChecksum() {
  let data = this.data.slice(0, this.written);
  let hash = digest.hash256(data);
  hash.copy(this.data, this.written, 0, 4);
  this.written += 4;
};

/**
 * Fill N bytes with value.
 * @param {Number} value
 * @param {Number} size
 */

StaticWriter.prototype.fill = function fill(value, size) {
  assert(size >= 0);

  if (size === 0)
    return;

  this.data.fill(value, this.written, this.written + size);
  this.written += size;
};

/*
 * Expose
 */

module.exports = StaticWriter;
