/**
 * reader.js - buffer reader for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var utils = require('./utils');
var assert = utils.assert;

/**
 * BufferReader
 */

function BufferReader(data, offset) {
  if (data instanceof BufferReader)
    return data;
  this.data = data;
  this.offset = offset || 0;
  this.stack = [];
}

BufferReader.prototype.start = function start() {
  this.stack.push(this.offset);
};

BufferReader.prototype.end = function end() {
  assert(this.stack.length > 0);

  var start = this.stack.pop();
  var end = this.offset;

  if (this.stack.length === 0) {
    delete this.offset;
    delete this.stack;
    delete this.data;
  }

  return end - start;
};

BufferReader.prototype.endData = function endData() {
  assert(this.stack.length > 0);

  var start = this.stack.pop();
  var end = this.offset;
  var size = end - start;
  var data = this.data;

  if (this.stack.length === 0) {
    delete this.offset;
    delete this.stack;
    delete this.data;
  }

  if (size === data.length)
    return data;

  return utils.slice(data, start, end);
};

BufferReader.prototype.readU8 = function readU8() {
  assert(this.offset + 1 <= this.data.length);
  var ret = utils.readU8(this.data, this.offset);
  this.offset += 1;
  return ret;
};

BufferReader.prototype.readU16 = function readU16() {
  assert(this.offset + 2 <= this.data.length);
  var ret = utils.readU16(this.data, this.offset);
  this.offset += 2;
  return ret;
};

BufferReader.prototype.readU16BE = function readU16BE() {
  assert(this.offset + 2 <= this.data.length);
  var ret = utils.readU16BE(this.data, this.offset);
  this.offset += 2;
  return ret;
};

BufferReader.prototype.readU32 = function readU32() {
  assert(this.offset + 4 <= this.data.length);
  var ret = utils.readU32(this.data, this.offset);
  this.offset += 4;
  return ret;
};

BufferReader.prototype.readU32BE = function readU32BE() {
  assert(this.offset + 4 <= this.data.length);
  var ret = utils.readU32BE(this.data, this.offset);
  this.offset += 4;
  return ret;
};

BufferReader.prototype.readU64 = function readU64() {
  assert(this.offset + 8 <= this.data.length);
  var ret = utils.readU64(this.data, this.offset);
  this.offset += 8;
  return ret;
};

BufferReader.prototype.readU64BE = function readU64BE() {
  assert(this.offset + 8 <= this.data.length);
  var ret = utils.readU64BE(this.data, this.offset);
  this.offset += 8;
  return ret;
};

BufferReader.prototype.read8 = function read8() {
  assert(this.offset + 1 <= this.data.length);
  var ret = utils.read8(this.data, this.offset);
  this.offset += 1;
  return ret;
};

BufferReader.prototype.read16 = function read16() {
  assert(this.offset + 2 <= this.data.length);
  var ret = utils.read16(this.data, this.offset);
  this.offset += 2;
  return ret;
};

BufferReader.prototype.read16BE = function read16BE() {
  assert(this.offset + 2 <= this.data.length);
  var ret = utils.read16BE(this.data, this.offset);
  this.offset += 2;
  return ret;
};

BufferReader.prototype.read32 = function read32() {
  assert(this.offset + 4 <= this.data.length);
  var ret = utils.read32(this.data, this.offset);
  this.offset += 4;
  return ret;
};

BufferReader.prototype.read32BE = function read32BE() {
  assert(this.offset + 4 <= this.data.length);
  var ret = utils.read32BE(this.data, this.offset);
  this.offset += 4;
  return ret;
};

BufferReader.prototype.read64 = function read64() {
  assert(this.offset + 8 <= this.data.length);
  var ret = utils.read64(this.data, this.offset);
  this.offset += 8;
  return ret;
};

BufferReader.prototype.read64BE = function read64BE() {
  assert(this.offset + 8 <= this.data.length);
  var ret = utils.read64BE(this.data, this.offset);
  this.offset += 8;
  return ret;
};

BufferReader.prototype.readBytes = function readBytes(size) {
  assert(size >= 0);
  assert(this.offset + size <= this.data.length);
  var ret = utils.slice(this.data, this.offset, this.offset + size);
  this.offset += size;
  return ret;
};

BufferReader.prototype.readString = function readString(enc, size) {
  assert(size >= 0);
  assert(this.offset + size <= this.data.length);
  var ret = this.data.toString(enc, this.offset, this.offset + size);
  this.offset += size;
  return ret;
};

BufferReader.prototype.readHash = function readHash(enc) {
  if (enc)
    return this.readBytes(32).toString(enc);
  return this.readBytes(32);
};

BufferReader.prototype.readVarString = function readVarString(enc) {
  return this.readString(enc, this.readUIntv());
};

BufferReader.prototype.readVarBytes = function readVarBytes() {
  return this.readBytes(this.readUIntv());
};

BufferReader.prototype.readNullString = function readNullString(enc) {
  assert(this.offset + 1 <= this.data.length);
  for (var i = this.offset; i < this.data.length; i++) {
    if (this.data[i] === 0)
      break;
  }
  assert(i !== this.data.length);
  var ret = this.readString(enc, i - this.offset);
  this.offset = i + 1;
  return ret;
};

BufferReader.prototype.left = function left() {
  assert(this.offset <= this.data.length);
  return this.data.length - this.offset;
};

BufferReader.prototype.readIntv = function readIntv() {
  assert(this.offset + 1 <= this.data.length);
  var result = utils.readIntv(this.data, this.offset);
  assert(result.off <= this.data.length);
  this.offset = result.off;
  return result.r;
};

BufferReader.prototype.readUIntv = function readUIntv() {
  var result = this.readIntv();
  assert(result >= 0);
  return result;
};

/**
 * Expose
 */

module.exports = BufferReader;
