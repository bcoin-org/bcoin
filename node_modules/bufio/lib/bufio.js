/*!
 * bufio.js - buffer utilities for javascript
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const custom = require('./custom');
const encoding = require('./encoding');
const enforce = require('./enforce');
const EncodingError = require('./error');
const BufferReader = require('./reader');
const BufferWriter = require('./writer');
const StaticWriter = require('./staticwriter');
const Struct = require('./struct');

exports.custom = custom;
exports.encoding = encoding;
exports.EncodingError = EncodingError;
exports.BufferReader = BufferReader;
exports.BufferWriter = BufferWriter;
exports.StaticWriter = StaticWriter;
exports.Struct = Struct;

exports.read = function read(data, zeroCopy) {
  return new BufferReader(data, zeroCopy);
};

exports.write = function write(size) {
  return size != null
    ? new StaticWriter(size)
    : new BufferWriter();
};

exports.pool = function pool(size) {
  return StaticWriter.pool(size);
};

function _read(func, size) {
  return function(data, off) {
    enforce(Buffer.isBuffer(data), 'data', 'buffer');
    enforce((off >>> 0) === off, 'off', 'integer');

    if (off + size > data.length)
      throw new EncodingError(off, 'Out of bounds read');

    return func(data, off);
  };
}

function _readn(func) {
  return function(data, off, len) {
    enforce(Buffer.isBuffer(data), 'data', 'buffer');
    enforce((off >>> 0) === off, 'off', 'integer');
    enforce((len >>> 0) === len, 'len', 'integer');

    if (off + len > data.length)
      throw new EncodingError(off, 'Out of bounds read');

    return func(data, off, len);
  };
}

function _readvar(func) {
  return function(data, off) {
    enforce(Buffer.isBuffer(data), 'data', 'buffer');
    enforce((off >>> 0) === off, 'off', 'integer');
    return func(data, off);
  };
}

function _write(func, size) {
  return function(data, num, off) {
    enforce(Buffer.isBuffer(data), 'data', 'buffer');
    enforce((off >>> 0) === off, 'off', 'integer');

    if (off + size > data.length)
      throw new EncodingError(off, 'Out of bounds write');

    return func(data, num, off);
  };
}

function _writen(func) {
  return function(data, num, off, len) {
    enforce(Buffer.isBuffer(data), 'data', 'buffer');
    enforce((off >>> 0) === off, 'off', 'integer');
    enforce((len >>> 0) === len, 'len', 'integer');

    if (off + len > data.length)
      throw new EncodingError(off, 'Out of bounds write');

    return func(data, num, off, len);
  };
}

function _writecb(func, size) {
  return function(data, num, off) {
    enforce(Buffer.isBuffer(data), 'data', 'buffer');
    enforce((off >>> 0) === off, 'off', 'integer');

    if (off + size(num) > data.length)
      throw new EncodingError(off, 'Out of bounds write');

    return func(data, num, off);
  };
}

exports.readU = _readn(encoding.readU);
exports.readU64 = _read(encoding.readU64, 8);
exports.readU56 = _read(encoding.readU56, 7);
exports.readU48 = _read(encoding.readU48, 6);
exports.readU40 = _read(encoding.readU40, 5);
exports.readU32 = _read(encoding.readU32, 4);
exports.readU24 = _read(encoding.readU24, 3);
exports.readU16 = _read(encoding.readU16, 2);
exports.readU8 = _read(encoding.readU8, 1);

exports.readUBE = _readn(encoding.readUBE);
exports.readU64BE = _read(encoding.readU64BE, 8);
exports.readU56BE = _read(encoding.readU56BE, 7);
exports.readU48BE = _read(encoding.readU48BE, 6);
exports.readU40BE = _read(encoding.readU40BE, 5);
exports.readU32BE = _read(encoding.readU32BE, 4);
exports.readU24BE = _read(encoding.readU24BE, 3);
exports.readU16BE = _read(encoding.readU16BE, 2);

exports.readI = _readn(encoding.readI);
exports.readI64 = _read(encoding.readI64, 8);
exports.readI56 = _read(encoding.readI56, 7);
exports.readI48 = _read(encoding.readI48, 6);
exports.readI40 = _read(encoding.readI40, 5);
exports.readI32 = _read(encoding.readI32, 4);
exports.readI24 = _read(encoding.readI24, 3);
exports.readI16 = _read(encoding.readI16, 2);
exports.readI8 = _read(encoding.readI8, 1);

exports.readIBE = _readn(encoding.readIBE);
exports.readI64BE = _read(encoding.readI64BE, 8);
exports.readI56BE = _read(encoding.readI56BE, 7);
exports.readI48BE = _read(encoding.readI48BE, 6);
exports.readI40BE = _read(encoding.readI40BE, 5);
exports.readI32BE = _read(encoding.readI32BE, 4);
exports.readI24BE = _read(encoding.readI24BE, 3);
exports.readI16BE = _read(encoding.readI16BE, 2);

exports.readFloat = _read(encoding.readFloat, 4);
exports.readFloatBE = _read(encoding.readFloatBE, 4);
exports.readDouble = _read(encoding.readDouble, 8);
exports.readDoubleBE = _read(encoding.readDoubleBE, 8);

exports.writeU = _writen(encoding.writeU);
exports.writeU64 = _write(encoding.writeU64, 8);
exports.writeU56 = _write(encoding.writeU56, 7);
exports.writeU48 = _write(encoding.writeU48, 6);
exports.writeU40 = _write(encoding.writeU40, 5);
exports.writeU32 = _write(encoding.writeU32, 4);
exports.writeU24 = _write(encoding.writeU24, 3);
exports.writeU16 = _write(encoding.writeU16, 2);
exports.writeU8 = _write(encoding.writeU8, 1);

exports.writeUBE = _writen(encoding.writeUBE);
exports.writeU64BE = _write(encoding.writeU64BE, 8);
exports.writeU56BE = _write(encoding.writeU56BE, 7);
exports.writeU48BE = _write(encoding.writeU48BE, 6);
exports.writeU40BE = _write(encoding.writeU40BE, 5);
exports.writeU32BE = _write(encoding.writeU32BE, 4);
exports.writeU24BE = _write(encoding.writeU24BE, 3);
exports.writeU16BE = _write(encoding.writeU16BE, 2);

exports.writeI = _writen(encoding.writeI);
exports.writeI64 = _write(encoding.writeI64, 8);
exports.writeI56 = _write(encoding.writeI56, 7);
exports.writeI48 = _write(encoding.writeI48, 6);
exports.writeI40 = _write(encoding.writeI40, 5);
exports.writeI32 = _write(encoding.writeI32, 4);
exports.writeI24 = _write(encoding.writeI24, 3);
exports.writeI16 = _write(encoding.writeI16, 2);
exports.writeI8 = _write(encoding.writeI8, 1);

exports.writeIBE = _writen(encoding.writeIBE);
exports.writeI64BE = _write(encoding.writeI64BE, 8);
exports.writeI56BE = _write(encoding.writeI56BE, 7);
exports.writeI48BE = _write(encoding.writeI48BE, 6);
exports.writeI40BE = _write(encoding.writeI40BE, 5);
exports.writeI32BE = _write(encoding.writeI32BE, 4);
exports.writeI24BE = _write(encoding.writeI24BE, 3);
exports.writeI16BE = _write(encoding.writeI16BE, 2);

exports.writeFloat = _write(encoding.writeFloat, 4);
exports.writeFloatBE = _write(encoding.writeFloatBE, 4);
exports.writeDouble = _write(encoding.writeDouble, 8);
exports.writeDoubleBE = _write(encoding.writeDoubleBE, 8);

exports.readVarint = _readvar(encoding.readVarint);
exports.writeVarint = _writecb(encoding.writeVarint, encoding.sizeVarint);
exports.sizeVarint = encoding.sizeVarint;
exports.readVarint2 = _readvar(encoding.readVarint2);
exports.writeVarint2 = _writecb(encoding.writeVarint2, encoding.sizeVarint2);
exports.sizeVarint2 = encoding.sizeVarint2;

exports.sliceBytes = encoding.sliceBytes;
exports.readBytes = encoding.readBytes;
exports.writeBytes = encoding.writeBytes;
exports.readString = encoding.readString;
exports.writeString = encoding.writeString;

exports.realloc = encoding.realloc;
exports.copy = encoding.copy;
exports.concat = encoding.concat;

exports.sizeVarBytes = encoding.sizeVarBytes;
exports.sizeVarlen = encoding.sizeVarlen;
exports.sizeVarString = encoding.sizeVarString;
