/*!
 * staticwriter.js - buffer writer for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const encoding = require('bbuf/lib/encoding');

const POOL0 = Buffer.allocUnsafe(0);
const POOL8 = Buffer.allocUnsafe(1);
const POOL16 = Buffer.allocUnsafe(2);
const POOL24 = Buffer.allocUnsafe(3);
const POOL32 = Buffer.allocUnsafe(4);
const POOL40 = Buffer.allocUnsafe(5);
const POOL48 = Buffer.allocUnsafe(6);
const POOL56 = Buffer.allocUnsafe(7);
const POOL64 = Buffer.allocUnsafe(8);
const POOL72 = Buffer.allocUnsafe(9);
const POOL256 = Buffer.allocUnsafe(32);

const poolBySize = [
  POOL0,
  POOL8,
  POOL16,
  POOL24,
  POOL32,
  POOL40,
  POOL48,
  POOL56,
  POOL64,
  POOL72
];

/**
 * Statically allocated buffer writer.
 * @alias module:utils.HashWriter
 * @constructor
 * @param {Number} size
 */

function HashWriter(Hash, ...args) {
  if (!(this instanceof HashWriter))
    return new HashWriter(Hash, ...args);

  this.ctx = new Hash().init(...args);
}

/**
 * Allocate and render the final buffer.
 * @returns {Buffer} Rendered buffer.
 */

HashWriter.prototype.init = function init(...args) {
  return this.ctx.init(...args);
};

/**
 * Allocate and render the final buffer.
 * @returns {Buffer} Rendered buffer.
 */

HashWriter.prototype.update = function update(data) {
  return this.ctx.update(data);
};

/**
 * Allocate and render the final buffer.
 * @returns {Buffer} Rendered buffer.
 */

HashWriter.prototype.final = function final() {
  return this.ctx.final();
};

/**
 * Get size of data written so far.
 * @returns {Number}
 */

HashWriter.prototype.getSize = function getSize() {
  assert(false);
};

/**
 * Seek to relative offset.
 * @param {Number} offset
 */

HashWriter.prototype.seek = function seek(offset) {
  assert(false);
};

/**
 * Destroy the buffer writer.
 */

HashWriter.prototype.destroy = function destroy() {
  assert(false);
};

/**
 * Write uint8.
 * @param {Number} value
 */

HashWriter.prototype.writeU8 = function writeU8(value) {
  POOL8.writeUInt8(value, 0, true);
  this.ctx.update(POOL8);
};

/**
 * Write uint16le.
 * @param {Number} value
 */

HashWriter.prototype.writeU16 = function writeU16(value) {
  POOL16.writeUInt16LE(value, 0, true);
  this.ctx.update(POOL16);
};

/**
 * Write uint16be.
 * @param {Number} value
 */

HashWriter.prototype.writeU16BE = function writeU16BE(value) {
  POOL16.writeUInt16BE(value, 0, true);
  this.ctx.update(POOL16);
};

/**
 * Write uint32le.
 * @param {Number} value
 */

HashWriter.prototype.writeU32 = function writeU32(value) {
  POOL32.writeUInt32LE(value, 0, true);
  this.ctx.update(POOL32);
};

/**
 * Write uint32be.
 * @param {Number} value
 */

HashWriter.prototype.writeU32BE = function writeU32BE(value) {
  POOL32.writeUInt32BE(value, 0, true);
  this.ctx.update(POOL32);
};

/**
 * Write uint64le.
 * @param {Number} value
 */

HashWriter.prototype.writeU64 = function writeU64(value) {
  encoding.writeU64(POOL64, value, 0);
  this.ctx.update(POOL64);
};

/**
 * Write uint64be.
 * @param {Number} value
 */

HashWriter.prototype.writeU64BE = function writeU64BE(value) {
  encoding.writeU64BE(POOL64, value, 0);
  this.ctx.update(POOL64);
};

/**
 * Write uint64le.
 * @param {U64} value
 */

HashWriter.prototype.writeU64N = function writeU64N(value) {
  encoding.writeU64N(POOL64, value, 0);
  this.ctx.update(POOL64);
};

/**
 * Write uint64be.
 * @param {U64} value
 */

HashWriter.prototype.writeU64BEN = function writeU64BEN(value) {
  encoding.writeU64BEN(POOL64, value, 0);
  this.ctx.update(POOL64);
};

/**
 * Write int8.
 * @param {Number} value
 */

HashWriter.prototype.writeI8 = function writeI8(value) {
  POOL8.writeInt8(value, 0, true);
  this.ctx.update(POOL8);
};

/**
 * Write int16le.
 * @param {Number} value
 */

HashWriter.prototype.writeI16 = function writeI16(value) {
  POOL16.writeInt16LE(value, 0, true);
  this.ctx.update(POOL16);
};

/**
 * Write int16be.
 * @param {Number} value
 */

HashWriter.prototype.writeI16BE = function writeI16BE(value) {
  POOL16.writeInt16BE(value, 0, true);
  this.ctx.update(POOL16);
};

/**
 * Write int32le.
 * @param {Number} value
 */

HashWriter.prototype.writeI32 = function writeI32(value) {
  POOL32.writeInt32LE(value, 0, true);
  this.ctx.update(POOL32);
};

/**
 * Write int32be.
 * @param {Number} value
 */

HashWriter.prototype.writeI32BE = function writeI32BE(value) {
  POOL32.writeInt32BE(value, 0, true);
  this.ctx.update(POOL32);
};

/**
 * Write int64le.
 * @param {Number} value
 */

HashWriter.prototype.writeI64 = function writeI64(value) {
  encoding.writeI64(POOL64, value, 0);
  this.ctx.update(POOL64);
};

/**
 * Write int64be.
 * @param {Number} value
 */

HashWriter.prototype.writeI64BE = function writeI64BE(value) {
  encoding.writeI64BE(POOL64, value, 0);
  this.ctx.update(POOL64);
};

/**
 * Write int64le.
 * @param {I64} value
 */

HashWriter.prototype.writeI64N = function writeI64N(value) {
  encoding.writeI64N(POOL64, value, 0);
  this.ctx.update(POOL64);
};

/**
 * Write int64be.
 * @param {I64} value
 */

HashWriter.prototype.writeI64BEN = function writeI64BEN(value) {
  encoding.writeI64BEN(POOL64, value, 0);
  this.ctx.update(POOL64);
};

/**
 * Write float le.
 * @param {Number} value
 */

HashWriter.prototype.writeFloat = function writeFloat(value) {
  POOL32.writeFloatLE(value, 0, true);
  this.ctx.update(POOL32);
};

/**
 * Write float be.
 * @param {Number} value
 */

HashWriter.prototype.writeFloatBE = function writeFloatBE(value) {
  POOL32.writeFloatBE(value, 0, true);
  this.ctx.update(POOL32);
};

/**
 * Write double le.
 * @param {Number} value
 */

HashWriter.prototype.writeDouble = function writeDouble(value) {
  POOL64.writeDoubleLE(value, 0, true);
  this.ctx.update(POOL64);
};

/**
 * Write double be.
 * @param {Number} value
 */

HashWriter.prototype.writeDoubleBE = function writeDoubleBE(value) {
  POOL64.writeDoubleBE(value, 0, true);
  this.ctx.update(POOL64);
};

/**
 * Write a varint.
 * @param {Number} value
 */

HashWriter.prototype.writeVarint = function writeVarint(value) {
  const size = encoding.sizeVarint(value);
  const pool = poolBySize[size];
  encoding.writeVarint(pool, value, 0);
  this.ctx.update(pool);
};

/**
 * Write a varint.
 * @param {U64} value
 */

HashWriter.prototype.writeVarintN = function writeVarintN(value) {
  const size = encoding.sizeVarintN(value);
  const pool = poolBySize[size];
  encoding.writeVarintN(pool, value, 0);
  this.ctx.update(pool);
};

/**
 * Write a varint (type 2).
 * @param {Number} value
 */

HashWriter.prototype.writeVarint2 = function writeVarint2(value) {
  const size = encoding.sizeVarint2(value);
  const pool = poolBySize[size];
  encoding.writeVarint2(pool, value, 0);
  this.ctx.update(pool);
};

/**
 * Write a varint (type 2).
 * @param {U64} value
 */

HashWriter.prototype.writeVarint2N = function writeVarint2N(value) {
  const size = encoding.sizeVarint2N(value);
  const pool = poolBySize[size];
  encoding.writeVarint2N(pool, value, 0);
  this.ctx.update(pool);
};

/**
 * Write bytes.
 * @param {Buffer} value
 */

HashWriter.prototype.writeBytes = function writeBytes(value) {
  this.ctx.update(value);
};

/**
 * Write bytes with a varint length before them.
 * @param {Buffer} value
 */

HashWriter.prototype.writeVarBytes = function writeVarBytes(value) {
  this.writeVarint(value.length);
  this.writeBytes(value);
};

/**
 * Copy bytes.
 * @param {Buffer} value
 * @param {Number} start
 * @param {Number} end
 */

HashWriter.prototype.copy = function copy(value, start, end) {
  this.ctx.update(value.slice(start, end));
};

/**
 * Write string to buffer.
 * @param {String} value
 * @param {String?} enc - Any buffer-supported encoding.
 */

HashWriter.prototype.writeString = function writeString(value, enc) {
  if (value.length === 0)
    return;

  if (typeof value === 'string')
    value = Buffer.from(value, enc);

  this.ctx.update(value);
};

/**
 * Write a 32 byte hash.
 * @param {Hash} value
 */

HashWriter.prototype.writeHash = function writeHash(value) {
  if (typeof value !== 'string') {
    assert(value.length === 32);
    this.writeBytes(value);
    return;
  }
  assert(value.length === 64);
  POOL256.write(value, 0, 'hex');
  this.ctx.update(POOL256);
};

/**
 * Write a string with a varint length before it.
 * @param {String}
 * @param {String?} enc - Any buffer-supported encoding.
 */

HashWriter.prototype.writeVarString = function writeVarString(value, enc) {
  if (value.length === 0) {
    this.writeVarint(0);
    return;
  }

  const size = Buffer.byteLength(value, enc);

  this.writeVarint(size);
  this.ctx.update(value, enc);
};

/**
 * Write a null-terminated string.
 * @param {String|Buffer}
 * @param {String?} enc - Any buffer-supported encoding.
 */

HashWriter.prototype.writeNullString = function writeNullString(value, enc) {
  this.writeString(value, enc);
  this.writeU8(0);
};

/**
 * Calculate and write a checksum for the data written so far.
 */

HashWriter.prototype.writeChecksum = function writeChecksum() {
  assert(false);
};

/**
 * Fill N bytes with value.
 * @param {Number} value
 * @param {Number} size
 */

HashWriter.prototype.fill = function fill(value, size) {
  assert(size >= 0);

  if (size === 0)
    return;

  if (size <= 32) {
    const data = POOL256.slice(0, size);
    data.fill(value);
    this.ctx.update(data);
    return;
  }

  const data = Buffer.allocUnsafe(size);
  data.fill(value);

  this.ctx.update(data);
};

/*
 * Expose
 */

module.exports = HashWriter;
