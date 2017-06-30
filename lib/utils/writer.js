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
const I8 = 8;
const I16 = 9;
const I16BE = 10;
const I32 = 11;
const I32BE = 12;
const I64 = 13;
const I64BE = 14;
const FL = 15;
const FLBE = 16;
const DBL = 17;
const DBLBE = 18;
const VARINT = 19;
const VARINT2 = 20;
const BYTES = 21;
const STR = 22;
const CHECKSUM = 23;
const FILL = 24;

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
  this.written = 0;
}

/**
 * Allocate and render the final buffer.
 * @param {Boolean?} keep - Do not destroy the writer.
 * @returns {Buffer} Rendered buffer.
 */

BufferWriter.prototype.render = function render(keep) {
  let data = Buffer.allocUnsafe(this.written);
  let off = 0;

  for (let op of this.ops) {
    switch (op.type) {
      case SEEK: off += op.value; break;
      case UI8: off = data.writeUInt8(op.value, off, true); break;
      case UI16: off = data.writeUInt16LE(op.value, off, true); break;
      case UI16BE: off = data.writeUInt16BE(op.value, off, true); break;
      case UI32: off = data.writeUInt32LE(op.value, off, true); break;
      case UI32BE: off = data.writeUInt32BE(op.value, off, true); break;
      case UI64: off = encoding.writeU64(data, op.value, off); break;
      case UI64BE: off = encoding.writeU64BE(data, op.value, off); break;
      case I8: off = data.writeInt8(op.value, off, true); break;
      case I16: off = data.writeInt16LE(op.value, off, true); break;
      case I16BE: off = data.writeInt16BE(op.value, off, true); break;
      case I32: off = data.writeInt32LE(op.value, off, true); break;
      case I32BE: off = data.writeInt32BE(op.value, off, true); break;
      case I64: off = encoding.write64(data, op.value, off); break;
      case I64BE: off = encoding.write64BE(data, op.value, off); break;
      case FL: off = data.writeFloatLE(op.value, off, true); break;
      case FLBE: off = data.writeFloatBE(op.value, off, true); break;
      case DBL: off = data.writeDoubleLE(op.value, off, true); break;
      case DBLBE: off = data.writeDoubleBE(op.value, off, true); break;
      case VARINT: off = encoding.writeVarint(data, op.value, off); break;
      case VARINT2: off = encoding.writeVarint2(data, op.value, off); break;
      case BYTES: off += op.value.copy(data, off); break;
      case STR: off += data.write(op.value, off, op.enc); break;
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

  if (!keep)
    this.destroy();

  return data;
};

/**
 * Get size of data written so far.
 * @returns {Number}
 */

BufferWriter.prototype.getSize = function getSize() {
  return this.written;
};

/**
 * Seek to relative offset.
 * @param {Number} offset
 */

BufferWriter.prototype.seek = function seek(offset) {
  this.written += offset;
  this.ops.push(new WriteOp(SEEK, offset));
};

/**
 * Destroy the buffer writer. Remove references to `ops`.
 */

BufferWriter.prototype.destroy = function destroy() {
  this.ops.length = 0;
  this.ops = null;
  this.written = null;
};

/**
 * Write uint8.
 * @param {Number} value
 */

BufferWriter.prototype.writeU8 = function writeU8(value) {
  this.written += 1;
  this.ops.push(new WriteOp(UI8, value));
};

/**
 * Write uint16le.
 * @param {Number} value
 */

BufferWriter.prototype.writeU16 = function writeU16(value) {
  this.written += 2;
  this.ops.push(new WriteOp(UI16, value));
};

/**
 * Write uint16be.
 * @param {Number} value
 */

BufferWriter.prototype.writeU16BE = function writeU16BE(value) {
  this.written += 2;
  this.ops.push(new WriteOp(UI16BE, value));
};

/**
 * Write uint32le.
 * @param {Number} value
 */

BufferWriter.prototype.writeU32 = function writeU32(value) {
  this.written += 4;
  this.ops.push(new WriteOp(UI32, value));
};

/**
 * Write uint32be.
 * @param {Number} value
 */

BufferWriter.prototype.writeU32BE = function writeU32BE(value) {
  this.written += 4;
  this.ops.push(new WriteOp(UI32BE, value));
};

/**
 * Write uint64le.
 * @param {Number} value
 */

BufferWriter.prototype.writeU64 = function writeU64(value) {
  this.written += 8;
  this.ops.push(new WriteOp(UI64, value));
};

/**
 * Write uint64be.
 * @param {Number} value
 */

BufferWriter.prototype.writeU64BE = function writeU64BE(value) {
  this.written += 8;
  this.ops.push(new WriteOp(UI64BE, value));
};

/**
 * Write uint64le.
 * @param {BN} value
 */

BufferWriter.prototype.writeU64BN = function writeU64BN(value) {
  assert(false, 'Not implemented.');
};

/**
 * Write uint64be.
 * @param {BN} value
 */

BufferWriter.prototype.writeU64BEBN = function writeU64BEBN(value) {
  assert(false, 'Not implemented.');
};

/**
 * Write int8.
 * @param {Number} value
 */

BufferWriter.prototype.write8 = function write8(value) {
  this.written += 1;
  this.ops.push(new WriteOp(I8, value));
};

/**
 * Write int16le.
 * @param {Number} value
 */

BufferWriter.prototype.write16 = function write16(value) {
  this.written += 2;
  this.ops.push(new WriteOp(I16, value));
};

/**
 * Write int16be.
 * @param {Number} value
 */

BufferWriter.prototype.write16BE = function write16BE(value) {
  this.written += 2;
  this.ops.push(new WriteOp(I16BE, value));
};

/**
 * Write int32le.
 * @param {Number} value
 */

BufferWriter.prototype.write32 = function write32(value) {
  this.written += 4;
  this.ops.push(new WriteOp(I32, value));
};

/**
 * Write int32be.
 * @param {Number} value
 */

BufferWriter.prototype.write32BE = function write32BE(value) {
  this.written += 4;
  this.ops.push(new WriteOp(I32BE, value));
};

/**
 * Write int64le.
 * @param {Number} value
 */

BufferWriter.prototype.write64 = function write64(value) {
  this.written += 8;
  this.ops.push(new WriteOp(I64, value));
};

/**
 * Write int64be.
 * @param {Number} value
 */

BufferWriter.prototype.write64BE = function write64BE(value) {
  this.written += 8;
  this.ops.push(new WriteOp(I64BE, value));
};

/**
 * Write int64le.
 * @param {BN} value
 */

BufferWriter.prototype.write64BN = function write64BN(value) {
  assert(false, 'Not implemented.');
};

/**
 * Write int64be.
 * @param {BN} value
 */

BufferWriter.prototype.write64BEBN = function write64BEBN(value) {
  assert(false, 'Not implemented.');
};

/**
 * Write float le.
 * @param {Number} value
 */

BufferWriter.prototype.writeFloat = function writeFloat(value) {
  this.written += 4;
  this.ops.push(new WriteOp(FL, value));
};

/**
 * Write float be.
 * @param {Number} value
 */

BufferWriter.prototype.writeFloatBE = function writeFloatBE(value) {
  this.written += 4;
  this.ops.push(new WriteOp(FLBE, value));
};

/**
 * Write double le.
 * @param {Number} value
 */

BufferWriter.prototype.writeDouble = function writeDouble(value) {
  this.written += 8;
  this.ops.push(new WriteOp(DBL, value));
};

/**
 * Write double be.
 * @param {Number} value
 */

BufferWriter.prototype.writeDoubleBE = function writeDoubleBE(value) {
  this.written += 8;
  this.ops.push(new WriteOp(DBLBE, value));
};

/**
 * Write a varint.
 * @param {Number} value
 */

BufferWriter.prototype.writeVarint = function writeVarint(value) {
  this.written += encoding.sizeVarint(value);
  this.ops.push(new WriteOp(VARINT, value));
};

/**
 * Write a varint.
 * @param {BN} value
 */

BufferWriter.prototype.writeVarintBN = function writeVarintBN(value) {
  assert(false, 'Not implemented.');
};

/**
 * Write a varint (type 2).
 * @param {Number} value
 */

BufferWriter.prototype.writeVarint2 = function writeVarint2(value) {
  this.written += encoding.sizeVarint2(value);
  this.ops.push(new WriteOp(VARINT2, value));
};

/**
 * Write a varint (type 2).
 * @param {BN} value
 */

BufferWriter.prototype.writeVarint2BN = function writeVarint2BN(value) {
  assert(false, 'Not implemented.');
};

/**
 * Write bytes.
 * @param {Buffer} value
 */

BufferWriter.prototype.writeBytes = function writeBytes(value) {
  if (value.length === 0)
    return;

  this.written += value.length;
  this.ops.push(new WriteOp(BYTES, value));
};

/**
 * Write bytes with a varint length before them.
 * @param {Buffer} value
 */

BufferWriter.prototype.writeVarBytes = function writeVarBytes(value) {
  this.written += encoding.sizeVarint(value.length);
  this.ops.push(new WriteOp(VARINT, value.length));

  if (value.length === 0)
    return;

  this.written += value.length;
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

  this.written += Buffer.byteLength(value, enc);
  this.ops.push(new WriteOp(STR, value, enc));
};

/**
 * Write a 32 byte hash.
 * @param {Hash} value
 */

BufferWriter.prototype.writeHash = function writeHash(value) {
  if (typeof value !== 'string') {
    assert(value.length === 32);
    return this.writeBytes(value);
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
  let size;

  if (value.length === 0) {
    this.ops.push(new WriteOp(VARINT, 0));
    return;
  }

  size = Buffer.byteLength(value, enc);

  this.written += encoding.sizeVarint(size);
  this.written += size;

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
  this.written += 4;
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

  this.written += size;
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
