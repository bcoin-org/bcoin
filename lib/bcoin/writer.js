/*!
 * writer.js - buffer writer for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

var utils = require('./utils');
var assert = utils.assert;

/*
 * Constants
 */

var SEEK = 0;
var UI8 = 1;
var UI16 = 2;
var UI16BE = 3;
var UI32 = 4;
var UI32BE = 5;
var UI64 = 6;
var UI64BE = 7;
var I8 = 8;
var I16 = 9;
var I16BE = 10;
var I32 = 11;
var I32BE = 12;
var I64 = 13;
var I64BE = 14;
var FL = 15;
var FLBE = 16;
var DBL = 17;
var DBLBE = 18;
var VARINT = 19;
var VARINT2 = 20;
var BYTES = 21;
var STR = 22;
var CHECKSUM = 23;
var FILL = 24;

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
 * @exports BufferWriter
 * @constructor
 * @param {(BufferWriter|Object)?} options
 */

function BufferWriter(options) {
  if (options instanceof BufferWriter)
    return options;

  if (!(this instanceof BufferWriter))
    return new BufferWriter(options);

  this.data = [];
  this.written = 0;
}

/**
 * Allocate and render the final buffer.
 * @param {Boolean?} keep - Do not destroy the writer.
 * @returns {Buffer} Rendered buffer.
 */

BufferWriter.prototype.render = function render(keep) {
  var data = new Buffer(this.written);
  var off = 0;
  var i, item;

  for (i = 0; i < this.data.length; i++) {
    item = this.data[i];
    switch (item[0]) {
      case SEEK: off += item[1]; break;
      case UI8: off = data.writeUInt8(item[1], off, true); break;
      case UI16: off = data.writeUInt16LE(item[1], off, true); break;
      case UI16BE: off = data.writeUInt16BE(item[1], off, true); break;
      case UI32: off = data.writeUInt32LE(item[1], off, true); break;
      case UI32BE: off = data.writeUInt32BE(item[1], off, true); break;
      case UI64: off = utils.writeU64(data, item[1], off); break;
      case UI64BE: off = utils.writeU64BE(data, item[1], off); break;
      case I8: off = data.writeInt8(item[1], off, true); break;
      case I16: off = data.writeInt16LE(item[1], off, true); break;
      case I16BE: off = data.writeInt16BE(item[1], off, true); break;
      case I32: off = data.writeInt32LE(item[1], off, true); break;
      case I32BE: off = data.writeInt32BE(item[1], off, true); break;
      case I64: off = utils.write64(data, item[1], off); break;
      case I64BE: off = utils.write64BE(data, item[1], off); break;
      case FL: off = data.writeFloatLE(item[1], off, true); break;
      case FLBE: off = data.writeFloatBE(item[1], off, true); break;
      case DBL: off = data.writeDoubleLE(item[1], off, true); break;
      case DBLBE: off = data.writeDoubleBE(item[1], off, true); break;
      case VARINT: off = utils.writeVarint(data, item[1], off); break;
      case VARINT2: off = utils.writeVarint2(data, item[1], off); break;
      case BYTES: off += item[1].copy(data, off); break;
      case STR: off += data.write(item[1], off, item[2]); break;
      case CHECKSUM:
        off += utils.checksum(data.slice(0, off)).copy(data, off);
        break;
      case FILL:
        data.fill(item[1], off, off + item[2]);
        off += item[2];
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
  this.data.push([SEEK, offset]);
};

/**
 * Destroy the buffer writer. Remove references to `data`.
 */

BufferWriter.prototype.destroy = function destroy() {
  this.data.length = 0;
  delete this.data;
  delete this.written;
};

/**
 * Write uint8.
 * @param {Number} value
 */

BufferWriter.prototype.writeU8 = function writeU8(value) {
  this.written += 1;
  this.data.push([UI8, value]);
};

/**
 * Write uint16le.
 * @param {Number} value
 */

BufferWriter.prototype.writeU16 = function writeU16(value) {
  this.written += 2;
  this.data.push([UI16, value]);
};

/**
 * Write uint16be.
 * @param {Number} value
 */

BufferWriter.prototype.writeU16BE = function writeU16BE(value) {
  this.written += 2;
  this.data.push([UI16BE, value]);
};

/**
 * Write uint32le.
 * @param {Number} value
 */

BufferWriter.prototype.writeU32 = function writeU32(value) {
  this.written += 4;
  this.data.push([UI32, value]);
};

/**
 * Write uint32be.
 * @param {Number} value
 */

BufferWriter.prototype.writeU32BE = function writeU32BE(value) {
  this.written += 4;
  this.data.push([UI32BE, value]);
};

/**
 * Write uint64le.
 * @param {BN|Number} value
 */

BufferWriter.prototype.writeU64 = function writeU64(value) {
  this.written += 8;
  this.data.push([UI64, value]);
};

/**
 * Write uint64be.
 * @param {BN|Number} value
 */

BufferWriter.prototype.writeU64BE = function writeU64BE(value) {
  this.written += 8;
  this.data.push([UI64BE, value]);
};

/**
 * Write int8.
 * @param {Number} value
 */

BufferWriter.prototype.write8 = function write8(value) {
  this.written += 1;
  this.data.push([I8, value]);
};

/**
 * Write int16le.
 * @param {Number} value
 */

BufferWriter.prototype.write16 = function write16(value) {
  this.written += 2;
  this.data.push([I16, value]);
};

/**
 * Write int16be.
 * @param {Number} value
 */

BufferWriter.prototype.write16BE = function write16BE(value) {
  this.written += 2;
  this.data.push([I16BE, value]);
};

/**
 * Write int32le.
 * @param {Number} value
 */

BufferWriter.prototype.write32 = function write32(value) {
  this.written += 4;
  this.data.push([I32, value]);
};

/**
 * Write int32be.
 * @param {Number} value
 */

BufferWriter.prototype.write32BE = function write32BE(value) {
  this.written += 4;
  this.data.push([I32BE, value]);
};

/**
 * Write int64le.
 * @param {BN|Number} value
 */

BufferWriter.prototype.write64 = function write64(value) {
  this.written += 8;
  this.data.push([I64, value]);
};

/**
 * Write int64be.
 * @param {BN|Number} value
 */

BufferWriter.prototype.write64BE = function write64BE(value) {
  this.written += 8;
  this.data.push([I64BE, value]);
};

/**
 * Write float le.
 * @param {Number} value
 */

BufferWriter.prototype.writeFloat = function writeFloat(value) {
  this.written += 4;
  this.data.push([FL, value]);
};

/**
 * Write float be.
 * @param {Number} value
 */

BufferWriter.prototype.writeFloatBE = function writeFloatBE(value) {
  this.written += 4;
  this.data.push([FLBE, value]);
};

/**
 * Write double le.
 * @param {Number} value
 */

BufferWriter.prototype.writeDouble = function writeDouble(value) {
  this.written += 8;
  this.data.push([DBL, value]);
};

/**
 * Write double be.
 * @param {Number} value
 */

BufferWriter.prototype.writeDoubleBE = function writeDoubleBE(value) {
  this.written += 8;
  this.data.push([DBLBE, value]);
};

/**
 * Write a varint.
 * @param {BN|Number} value
 */

BufferWriter.prototype.writeVarint = function writeVarint(value) {
  if (typeof value === 'number')
    assert(value >= 0);
  else
    assert(!value.isNeg());

  this.written += utils.sizeVarint(value);
  this.data.push([VARINT, value]);
};

/**
 * Write a varint (type 2).
 * @param {BN|Number} value
 */

BufferWriter.prototype.writeVarint2 = function writeVarint2(value) {
  if (typeof value === 'number')
    assert(value >= 0);
  else
    assert(!value.isNeg());

  this.written += utils.sizeVarint2(value);
  this.data.push([VARINT2, value]);
};

/**
 * Write bytes.
 * @param {Buffer} value
 */

BufferWriter.prototype.writeBytes = function writeBytes(value) {
  this.written += value.length;
  this.data.push([BYTES, value]);
};

/**
 * Write bytes with a varint length before them.
 * @param {Buffer} value
 */

BufferWriter.prototype.writeVarBytes = function writeVarBytes(value) {
  this.written += utils.sizeVarint(value.length);
  this.written += value.length;
  this.data.push([VARINT, value.length]);
  this.data.push([BYTES, value]);
};

/**
 * Write string to buffer.
 * @param {String|Buffer} value
 * @param {String?} enc - Any buffer-supported encoding.
 */

BufferWriter.prototype.writeString = function writeString(value, enc) {
  if (typeof value !== 'string')
    return this.writeBytes(value);
  this.written += Buffer.byteLength(value, enc);
  this.data.push([STR, value, enc]);
};

/**
 * Write a hash/hex-string.
 * @param {Hash|Buffer}
 */

BufferWriter.prototype.writeHash = function writeHash(value) {
  this.writeString(value, 'hex');
};

/**
 * Write a string with a varint length before it.
 * @param {String|Buffer}
 * @param {String?} enc - Any buffer-supported encoding.
 */

BufferWriter.prototype.writeVarString = function writeVarString(value, enc) {
  var size;

  if (typeof value !== 'string')
    return this.writeVarBytes(value);

  size = Buffer.byteLength(value, enc);

  this.written += utils.sizeVarint(size);
  this.written += size;

  this.data.push([VARINT, size]);
  this.data.push([STR, value, enc]);
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
  this.data.push([CHECKSUM]);
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
  this.data.push([FILL, value, size]);
};

/*
 * Expose
 */

module.exports = BufferWriter;
