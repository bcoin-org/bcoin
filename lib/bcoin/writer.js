/**
 * writer.js - buffer writer for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var utils = require('./utils');
var assert = utils.assert;

/**
 * BufferWriter
 */

function BufferWriter(options) {
  if (options instanceof BufferWriter)
    return options;

  if (!(this instanceof BufferWriter))
    return new BufferWriter(options);

  this.data = [];
  this.written = 0;
}

BufferWriter.prototype.render = function render() {
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
      case 'varint': off += utils.writeIntv(data, item[1], off); break;
      case 'bytes': off += utils.copy(item[1], data, off); break;
    }
  }

  return data;
};

BufferWriter.prototype.writeU8 = function writeU8(value) {
  this.written += 1;
  this.data.push(['u8', value]);
};

BufferWriter.prototype.writeU16 = function writeU16(value) {
  this.written += 2;
  this.data.push(['u16', value]);
};

BufferWriter.prototype.writeU16BE = function writeU16BE(value) {
  this.written += 2;
  this.data.push(['u16be', value]);
};

BufferWriter.prototype.writeU32 = function writeU32(value) {
  this.written += 4;
  this.data.push(['u32', value]);
};

BufferWriter.prototype.writeU32BE = function writeU32BE(value) {
  this.written += 4;
  this.data.push(['u32be', value]);
};

BufferWriter.prototype.writeU64 = function writeU64(value) {
  this.written += 8;
  this.data.push(['u64', value]);
};

BufferWriter.prototype.writeU64BE = function writeU64BE(value) {
  this.written += 8;
  this.data.push(['u64be', value]);
};

BufferWriter.prototype.write8 = function write8(value) {
  this.written += 1;
  this.data.push(['8', value]);
};

BufferWriter.prototype.write16 = function write16(value) {
  this.written += 2;
  this.data.push(['16', value]);
};

BufferWriter.prototype.write16BE = function write16BE(value) {
  this.written += 2;
  this.data.push(['16be', value]);
};

BufferWriter.prototype.write32 = function write32(value) {
  this.written += 4;
  this.data.push(['32', value]);
};

BufferWriter.prototype.write32BE = function write32BE(value) {
  this.written += 4;
  this.data.push(['32be', value]);
};

BufferWriter.prototype.write64 = function write64(value) {
  this.written += 8;
  this.data.push(['64', value]);
};

BufferWriter.prototype.write64BE = function write64BE(value) {
  this.written += 8;
  this.data.push(['64be', value]);
};

BufferWriter.prototype.writeBytes = function writeBytes(value) {
  this.written += value.length;
  this.data.push(['bytes', value]);
};

BufferWriter.prototype.getSize = function getSize() {
  return this.written;
};

BufferWriter.prototype.writeString = function writeString(value, enc) {
  if (typeof value === 'string')
    value = new Buffer(value, enc);
  this.writeBytes(value);
};

BufferWriter.prototype.writeHash = function writeHash(value) {
  if (typeof value === 'string')
    value = new Buffer(value, 'hex');
  this.writeBytes(value);
};

BufferWriter.prototype.writeVarString = function writeVarString(value, enc) {
  if (typeof value === 'string')
    value = new Buffer(value, enc);
  this.writeVarBytes(value);
};

BufferWriter.prototype.writeVarBytes = function writeVarBytes(value) {
  this.written += utils.sizeIntv(value.length);
  this.written += value.length;
  this.data.push(['varint', value.length]);
  this.data.push(['bytes', value]);
};

BufferWriter.prototype.writeNullString = function writeNullString(value, enc) {
  this.writeString(value, enc);
  this.writeU8(0);
};

BufferWriter.prototype.writeIntv = function writeIntv(value) {
  this.written += utils.sizeIntv(value);
  this.data.push(['varint', value]);
};

BufferWriter.prototype.writeUIntv = function writeUIntv(value) {
  this.written += utils.sizeIntv(value);
  this.data.push(['varint', value]);
};

/**
 * Expose
 */

module.exports = BufferWriter;
