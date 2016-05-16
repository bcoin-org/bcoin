/*!
 * writer.js - buffer writer for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

var utils = require('./utils');
var assert = utils.assert;

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
      case 'u8': off += utils.writeU8(data, item[1], off); break;
      case 'u16': off += utils.writeU16(data, item[1], off); break;
      case 'u16be': off += utils.writeU16BE(data, item[1], off); break;
      case 'u32': off += utils.writeU32(data, item[1], off); break;
      case 'u32be': off += utils.writeU32BE(data, item[1], off); break;
      case 'u64': off += utils.writeU64(data, item[1], off); break;
      case 'u64be': off += utils.writeU64BE(data, item[1], off); break;
      case '8': off += utils.write8(data, item[1], off); break;
      case '16': off += utils.write16(data, item[1], off); break;
      case '16be': off += utils.write16BE(data, item[1], off); break;
      case '32': off += utils.write32(data, item[1], off); break;
      case '32be': off += utils.write32BE(data, item[1], off); break;
      case '64': off += utils.write64(data, item[1], off); break;
      case '64be': off += utils.write64BE(data, item[1], off); break;
      case 'f': data.writeFloatLE(item[1], off, true); off += 4; break;
      case 'fbe': data.writeFloatBE(item[1], off, true); off += 4; break;
      case 'd': data.writeDoubleLE(item[1], off, true); off += 8; break;
      case 'dbe': data.writeDoubleBE(item[1], off, true); off += 8; break;
      case 'varint': off += utils.writeVarint(data, item[1], off); break;
      case 'bytes': off += item[1].copy(data, off); break;
      case 'str': off += data.write(item[1], off, item[2]); break;
      case 'checksum':
        off += utils.checksum(data.slice(0, off)).copy(data, off);
        break;
      // case 'seek': off += item[1]; break;
      // case 'fill':
      //   item[1].fill(item[1], off, off + item[2]);
      //   off += item[2];
      //   break;
    }
  }

  if (!keep)
    this.destroy();

  return data;
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
  this.data.push(['u8', value]);
};

/**
 * Write uint16le.
 * @param {Number} value
 */

BufferWriter.prototype.writeU16 = function writeU16(value) {
  this.written += 2;
  this.data.push(['u16', value]);
};

/**
 * Write uint16be.
 * @param {Number} value
 */

BufferWriter.prototype.writeU16BE = function writeU16BE(value) {
  this.written += 2;
  this.data.push(['u16be', value]);
};

/**
 * Write uint32le.
 * @param {Number} value
 */

BufferWriter.prototype.writeU32 = function writeU32(value) {
  this.written += 4;
  this.data.push(['u32', value]);
};

/**
 * Write uint32be.
 * @param {Number} value
 */

BufferWriter.prototype.writeU32BE = function writeU32BE(value) {
  this.written += 4;
  this.data.push(['u32be', value]);
};

/**
 * Write uint64le.
 * @param {BN|Number} value
 */

BufferWriter.prototype.writeU64 = function writeU64(value) {
  this.written += 8;
  this.data.push(['u64', value]);
};

/**
 * Write uint64be.
 * @param {BN|Number} value
 */

BufferWriter.prototype.writeU64BE = function writeU64BE(value) {
  this.written += 8;
  this.data.push(['u64be', value]);
};

/**
 * Write int8.
 * @param {Number} value
 */

BufferWriter.prototype.write8 = function write8(value) {
  this.written += 1;
  this.data.push(['8', value]);
};

/**
 * Write int16le.
 * @param {Number} value
 */

BufferWriter.prototype.write16 = function write16(value) {
  this.written += 2;
  this.data.push(['16', value]);
};

/**
 * Write int16be.
 * @param {Number} value
 */

BufferWriter.prototype.write16BE = function write16BE(value) {
  this.written += 2;
  this.data.push(['16be', value]);
};

/**
 * Write int32le.
 * @param {Number} value
 */

BufferWriter.prototype.write32 = function write32(value) {
  this.written += 4;
  this.data.push(['32', value]);
};

/**
 * Write int32be.
 * @param {Number} value
 */

BufferWriter.prototype.write32BE = function write32BE(value) {
  this.written += 4;
  this.data.push(['32be', value]);
};

/**
 * Write int64le.
 * @param {BN|Number} value
 */

BufferWriter.prototype.write64 = function write64(value) {
  this.written += 8;
  this.data.push(['64', value]);
};

/**
 * Write int64be.
 * @param {BN|Number} value
 */

BufferWriter.prototype.write64BE = function write64BE(value) {
  this.written += 8;
  this.data.push(['64be', value]);
};

/**
 * Write bytes.
 * @param {Buffer} value
 */

BufferWriter.prototype.writeBytes = function writeBytes(value) {
  this.written += value.length;
  this.data.push(['bytes', value]);
};

/**
 * Get size of data written so far.
 * @returns {Number}
 */

BufferWriter.prototype.getSize = function getSize() {
  return this.written;
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
  this.data.push(['str', value, enc]);
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

  this.data.push(['varint', size]);
  this.data.push(['str', value, enc]);
};

/**
 * Write bytes with a varint length before them.
 * @param {Buffer} value
 */

BufferWriter.prototype.writeVarBytes = function writeVarBytes(value) {
  this.written += utils.sizeVarint(value.length);
  this.written += value.length;
  this.data.push(['varint', value.length]);
  this.data.push(['bytes', value]);
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
 * Write a varint.
 * @param {BN|Number} value
 */

BufferWriter.prototype.writeVarint = function writeVarint(value) {
  assert(value >= 0);
  this.written += utils.sizeVarint(value);
  this.data.push(['varint', value]);
};

/**
 * Calculate and write a checksum for the data written so far.
 */

BufferWriter.prototype.writeChecksum = function writeChecksum() {
  this.written += 4;
  this.data.push(['checksum']);
};

/**
 * Fill N bytes with value.
 * @param {Number} value
 * @param {Number} size
 */

BufferWriter.prototype.fill = function fill(value, size) {
  var buf;

  assert(size >= 0);

  buf = new Buffer(size);
  buf.fill(value);

  this.written += buf.length;
  this.data.push(['bytes', buf]);
};

// BufferWriter.prototype.fill = function fill(value, size) {
//   assert(size >= 0);
//   this.written += size;
//   this.data.push(['fill', value, size]);
// };

/*
 * Seek to relative offset.
 * @param {Number} offset
 */

// BufferWriter.prototype.seek = function seek(offset) {
//   this.data.push(['seek', offset]);
// };

/**
 * Write float le.
 * @param {Number} value
 */

BufferWriter.prototype.writeFloat = function writeFloat(value) {
  assert(typeof value === 'number');
  this.written += 4;
  this.data.push(['f', value]);
};

/**
 * Write float be.
 * @param {Number} value
 */

BufferWriter.prototype.writeFloatBE = function writeFloatBE(value) {
  assert(typeof value === 'number');
  this.written += 4;
  this.data.push(['fbe', value]);
};

/**
 * Write double le.
 * @param {Number} value
 */

BufferWriter.prototype.writeDouble = function writeDouble(value) {
  assert(typeof value === 'number');
  this.written += 8;
  this.data.push(['d', value]);
};

/**
 * Write double be.
 * @param {Number} value
 */

BufferWriter.prototype.writeDoubleBE = function writeDoubleBE(value) {
  assert(typeof value === 'number');
  this.written += 8;
  this.data.push(['dbe', value]);
};

/*
 * Expose
 */

module.exports = BufferWriter;
