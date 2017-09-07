/*!
 * writer.js - buffer writer for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const encoding = require('./encoding');
const digest = require('../crypto/digest');

/*
 * Constants
 */

const SEEK = 0;
const UI8 = 1;
const UI16 = 2;
const UI16BE = 3;
const UI32 = 4;
const UI32BE = 5;
const UI64 = 6;
const UI64BE = 7;
const UI64N = 8;
const UI64BEN = 9;
const I8 = 10;
const I16 = 11;
const I16BE = 12;
const I32 = 13;
const I32BE = 14;
const I64 = 15;
const I64BE = 16;
const I64N = 17;
const I64BEN = 18;
const FL = 19;
const FLBE = 20;
const DBL = 21;
const DBLBE = 22;
const VARINT = 23;
const VARINTN = 24;
const VARINT2 = 25;
const VARINT2N = 26;
const BYTES = 27;
const STR = 28;
const CHECKSUM = 29;
const FILL = 30;

/**
 * An object that allows writing of buffers in a
 * sane manner. This buffer writer is extremely
 * optimized since it does not actually write
 * anything until `render` is called. It makes
 * one allocation: at the end, once it knows the
 * size of the buffer to be allocated. Because
 * of this, it can also act as a size calculator
 * which is useful for guaging block size
 * without actually serializing any data.
 * @alias module:utils.BufferWriter
 * @constructor
 */

function BufferWriter() {
  if (!(this instanceof BufferWriter))
    return new BufferWriter();

  this.ops = [];
  this.offset = 0;
}

/**
 * Allocate and render the final buffer.
 * @returns {Buffer} Rendered buffer.
 */

BufferWriter.prototype.render = function render() {
  const data = Buffer.allocUnsafe(this.offset);
  let off = 0;

  for (const op of this.ops) {
    switch (op.type) {
      case SEEK:
        off += op.value;
        break;
      case UI8:
        off = data.writeUInt8(op.value, off, true);
        break;
      case UI16:
        off = data.writeUInt16LE(op.value, off, true);
        break;
      case UI16BE:
        off = data.writeUInt16BE(op.value, off, true);
        break;
      case UI32:
        off = data.writeUInt32LE(op.value, off, true);
        break;
      case UI32BE:
        off = data.writeUInt32BE(op.value, off, true);
        break;
      case UI64:
        off = encoding.writeU64(data, op.value, off);
        break;
      case UI64BE:
        off = encoding.writeU64BE(data, op.value, off);
        break;
      case UI64N:
        off = encoding.writeU64N(data, op.value, off);
        break;
      case UI64BEN:
        off = encoding.writeU64BEN(data, op.value, off);
        break;
      case I8:
        off = data.writeInt8(op.value, off, true);
        break;
      case I16:
        off = data.writeInt16LE(op.value, off, true);
        break;
      case I16BE:
        off = data.writeInt16BE(op.value, off, true);
        break;
      case I32:
        off = data.writeInt32LE(op.value, off, true);
        break;
      case I32BE:
        off = data.writeInt32BE(op.value, off, true);
        break;
      case I64:
        off = encoding.writeI64(data, op.value, off);
        break;
      case I64BE:
        off = encoding.writeI64BE(data, op.value, off);
        break;
      case I64N:
        off = encoding.writeI64N(data, op.value, off);
        break;
      case I64BEN:
        off = encoding.writeI64BEN(data, op.value, off);
        break;
      case FL:
        off = data.writeFloatLE(op.value, off, true);
        break;
      case FLBE:
        off = data.writeFloatBE(op.value, off, true);
        break;
      case DBL:
        off = data.writeDoubleLE(op.value, off, true);
        break;
      case DBLBE:
        off = data.writeDoubleBE(op.value, off, true);
        break;
      case VARINT:
        off = encoding.writeVarint(data, op.value, off);
        break;
      case VARINTN:
        off = encoding.writeVarintN(data, op.value, off);
        break;
      case VARINT2:
        off = encoding.writeVarint2(data, op.value, off);
        break;
      case VARINT2N:
        off = encoding.writeVarint2N(data, op.value, off);
        break;
      case BYTES:
        off += op.value.copy(data, off);
        break;
      case STR:
        off += data.write(op.value, off, op.enc);
        break;
      case CHECKSUM:
        off += digest.hash256(data.slice(0, off)).copy(data, off, 0, 4);
        break;
      case FILL:
        data.fill(op.value, off, off + op.size);
        off += op.size;
        break;
      default:
        assert(false, 'Bad type.');
        break;
    }
  }

  assert(off === data.length);

  this.destroy();

  return data;
};

/**
 * Get size of data written so far.
 * @returns {Number}
 */

BufferWriter.prototype.getSize = function getSize() {
  return this.offset;
};

/**
 * Seek to relative offset.
 * @param {Number} offset
 */

BufferWriter.prototype.seek = function seek(offset) {
  this.offset += offset;
  this.ops.push(new WriteOp(SEEK, offset));
};

/**
 * Destroy the buffer writer. Remove references to `ops`.
 */

BufferWriter.prototype.destroy = function destroy() {
  this.ops.length = 0;
  this.offset = 0;
};

/**
 * Write uint8.
 * @param {Number} value
 */

BufferWriter.prototype.writeU8 = function writeU8(value) {
  this.offset += 1;
  this.ops.push(new WriteOp(UI8, value));
};

/**
 * Write uint16le.
 * @param {Number} value
 */

BufferWriter.prototype.writeU16 = function writeU16(value) {
  this.offset += 2;
  this.ops.push(new WriteOp(UI16, value));
};

/**
 * Write uint16be.
 * @param {Number} value
 */

BufferWriter.prototype.writeU16BE = function writeU16BE(value) {
  this.offset += 2;
  this.ops.push(new WriteOp(UI16BE, value));
};

/**
 * Write uint32le.
 * @param {Number} value
 */

BufferWriter.prototype.writeU32 = function writeU32(value) {
  this.offset += 4;
  this.ops.push(new WriteOp(UI32, value));
};

/**
 * Write uint32be.
 * @param {Number} value
 */

BufferWriter.prototype.writeU32BE = function writeU32BE(value) {
  this.offset += 4;
  this.ops.push(new WriteOp(UI32BE, value));
};

/**
 * Write uint64le.
 * @param {Number} value
 */

BufferWriter.prototype.writeU64 = function writeU64(value) {
  this.offset += 8;
  this.ops.push(new WriteOp(UI64, value));
};

/**
 * Write uint64be.
 * @param {Number} value
 */

BufferWriter.prototype.writeU64BE = function writeU64BE(value) {
  this.offset += 8;
  this.ops.push(new WriteOp(UI64BE, value));
};

/**
 * Write uint64le.
 * @param {U64} value
 */

BufferWriter.prototype.writeU64N = function writeU64N(value) {
  this.offset += 8;
  this.ops.push(new WriteOp(UI64N, value));
};

/**
 * Write uint64be.
 * @param {U64} value
 */

BufferWriter.prototype.writeU64BEN = function writeU64BEN(value) {
  this.offset += 8;
  this.ops.push(new WriteOp(UI64BEN, value));
};

/**
 * Write int8.
 * @param {Number} value
 */

BufferWriter.prototype.writeI8 = function writeI8(value) {
  this.offset += 1;
  this.ops.push(new WriteOp(I8, value));
};

/**
 * Write int16le.
 * @param {Number} value
 */

BufferWriter.prototype.writeI16 = function writeI16(value) {
  this.offset += 2;
  this.ops.push(new WriteOp(I16, value));
};

/**
 * Write int16be.
 * @param {Number} value
 */

BufferWriter.prototype.writeI16BE = function writeI16BE(value) {
  this.offset += 2;
  this.ops.push(new WriteOp(I16BE, value));
};

/**
 * Write int32le.
 * @param {Number} value
 */

BufferWriter.prototype.writeI32 = function writeI32(value) {
  this.offset += 4;
  this.ops.push(new WriteOp(I32, value));
};

/**
 * Write int32be.
 * @param {Number} value
 */

BufferWriter.prototype.writeI32BE = function writeI32BE(value) {
  this.offset += 4;
  this.ops.push(new WriteOp(I32BE, value));
};

/**
 * Write int64le.
 * @param {Number} value
 */

BufferWriter.prototype.writeI64 = function writeI64(value) {
  this.offset += 8;
  this.ops.push(new WriteOp(I64, value));
};

/**
 * Write int64be.
 * @param {Number} value
 */

BufferWriter.prototype.writeI64BE = function writeI64BE(value) {
  this.offset += 8;
  this.ops.push(new WriteOp(I64BE, value));
};

/**
 * Write int64le.
 * @param {I64} value
 */

BufferWriter.prototype.writeI64N = function writeI64N(value) {
  this.offset += 8;
  this.ops.push(new WriteOp(I64N, value));
};

/**
 * Write int64be.
 * @param {I64} value
 */

BufferWriter.prototype.writeI64BEN = function writeI64BEN(value) {
  this.offset += 8;
  this.ops.push(new WriteOp(I64BEN, value));
};

/**
 * Write float le.
 * @param {Number} value
 */

BufferWriter.prototype.writeFloat = function writeFloat(value) {
  this.offset += 4;
  this.ops.push(new WriteOp(FL, value));
};

/**
 * Write float be.
 * @param {Number} value
 */

BufferWriter.prototype.writeFloatBE = function writeFloatBE(value) {
  this.offset += 4;
  this.ops.push(new WriteOp(FLBE, value));
};

/**
 * Write double le.
 * @param {Number} value
 */

BufferWriter.prototype.writeDouble = function writeDouble(value) {
  this.offset += 8;
  this.ops.push(new WriteOp(DBL, value));
};

/**
 * Write double be.
 * @param {Number} value
 */

BufferWriter.prototype.writeDoubleBE = function writeDoubleBE(value) {
  this.offset += 8;
  this.ops.push(new WriteOp(DBLBE, value));
};

/**
 * Write a varint.
 * @param {Number} value
 */

BufferWriter.prototype.writeVarint = function writeVarint(value) {
  this.offset += encoding.sizeVarint(value);
  this.ops.push(new WriteOp(VARINT, value));
};

/**
 * Write a varint.
 * @param {U64} value
 */

BufferWriter.prototype.writeVarintN = function writeVarintN(value) {
  this.offset += encoding.sizeVarintN(value);
  this.ops.push(new WriteOp(VARINTN, value));
};

/**
 * Write a varint (type 2).
 * @param {Number} value
 */

BufferWriter.prototype.writeVarint2 = function writeVarint2(value) {
  this.offset += encoding.sizeVarint2(value);
  this.ops.push(new WriteOp(VARINT2, value));
};

/**
 * Write a varint (type 2).
 * @param {U64} value
 */

BufferWriter.prototype.writeVarint2N = function writeVarint2N(value) {
  this.offset += encoding.sizeVarint2N(value);
  this.ops.push(new WriteOp(VARINT2N, value));
};

/**
 * Write bytes.
 * @param {Buffer} value
 */

BufferWriter.prototype.writeBytes = function writeBytes(value) {
  if (value.length === 0)
    return;

  this.offset += value.length;
  this.ops.push(new WriteOp(BYTES, value));
};

/**
 * Write bytes with a varint length before them.
 * @param {Buffer} value
 */

BufferWriter.prototype.writeVarBytes = function writeVarBytes(value) {
  this.offset += encoding.sizeVarint(value.length);
  this.ops.push(new WriteOp(VARINT, value.length));

  if (value.length === 0)
    return;

  this.offset += value.length;
  this.ops.push(new WriteOp(BYTES, value));
};

/**
 * Copy bytes.
 * @param {Buffer} value
 * @param {Number} start
 * @param {Number} end
 */

BufferWriter.prototype.copy = function copy(value, start, end) {
  assert(end >= start);
  value = value.slice(start, end);
  this.writeBytes(value);
};

/**
 * Write string to buffer.
 * @param {String} value
 * @param {String?} enc - Any buffer-supported encoding.
 */

BufferWriter.prototype.writeString = function writeString(value, enc) {
  if (value.length === 0)
    return;

  this.offset += Buffer.byteLength(value, enc);
  this.ops.push(new WriteOp(STR, value, enc));
};

/**
 * Write a 32 byte hash.
 * @param {Hash} value
 */

BufferWriter.prototype.writeHash = function writeHash(value) {
  if (typeof value !== 'string') {
    assert(value.length === 32);
    this.writeBytes(value);
    return;
  }
  assert(value.length === 64);
  this.writeString(value, 'hex');
};

/**
 * Write a string with a varint length before it.
 * @param {String}
 * @param {String?} enc - Any buffer-supported encoding.
 */

BufferWriter.prototype.writeVarString = function writeVarString(value, enc) {
  if (value.length === 0) {
    this.ops.push(new WriteOp(VARINT, 0));
    return;
  }

  const size = Buffer.byteLength(value, enc);

  this.offset += encoding.sizeVarint(size);
  this.offset += size;

  this.ops.push(new WriteOp(VARINT, size));

  this.ops.push(new WriteOp(STR, value, enc));
};

/**
 * Write a null-terminated string.
 * @param {String|Buffer}
 * @param {String?} enc - Any buffer-supported encoding.
 */

BufferWriter.prototype.writeNullString = function writeNullString(value, enc) {
  this.writeString(value, enc);
  this.writeU8(0);
};

/**
 * Calculate and write a checksum for the data written so far.
 */

BufferWriter.prototype.writeChecksum = function writeChecksum() {
  this.offset += 4;
  this.ops.push(new WriteOp(CHECKSUM));
};

/**
 * Fill N bytes with value.
 * @param {Number} value
 * @param {Number} size
 */

BufferWriter.prototype.fill = function fill(value, size) {
  assert(size >= 0);

  if (size === 0)
    return;

  this.offset += size;
  this.ops.push(new WriteOp(FILL, value, null, size));
};

/*
 * Helpers
 */

function WriteOp(type, value, enc, size) {
  this.type = type;
  this.value = value;
  this.enc = enc;
  this.size = size;
}

/*
 * Expose
 */

module.exports = BufferWriter;
