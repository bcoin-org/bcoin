/*!
 * protobuf.js - protobufs for bcoin
 * Copyright (c) 2016-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/**
 * @module utils/protobuf
 */

var util = require('../utils/util');
var assert = require('assert');
var BufferReader = require('../utils/reader');
var BufferWriter = require('../utils/writer');

/*
 * Constants
 */

var wireType = {
  VARINT: 0,
  FIXED64: 1,
  DELIMITED: 2,
  START_GROUP: 3,
  END_GROUP: 4,
  FIXED32: 5
};

/**
 * ProtoReader
 * @constructor
 */

function ProtoReader(data, zeroCopy) {
  if (!(this instanceof ProtoReader))
    return new ProtoReader(data, zeroCopy);

  BufferReader.call(this, data, zeroCopy);
}

util.inherits(ProtoReader, BufferReader);

ProtoReader.prototype.readVarint = function readVarint() {
  var result = exports.readVarint(this.data, this.offset);
  this.offset += result.size;
  return result.value;
};

ProtoReader.prototype.readFieldValue = function readFieldValue(tag, opt) {
  var field = this.readField(tag, opt);
  if (!field)
    return -1;
  assert(field.value != null);
  return field.value;
};

ProtoReader.prototype.readFieldU64 = function readFieldU64(tag, opt) {
  var field = this.readField(tag, opt);
  if (!field)
    return -1;
  assert(field.type === wireType.VARINT || field.type === wireType.FIXED64);
  return field.value;
};

ProtoReader.prototype.readFieldU32 = function readFieldU32(tag, opt) {
  var field = this.readField(tag, opt);
  if (!field)
    return -1;
  assert(field.type === wireType.VARINT || field.type === wireType.FIXED32);
  return field.value;
};

ProtoReader.prototype.readFieldBytes = function readFieldBytes(tag, opt) {
  var field = this.readField(tag, opt);
  if (!field)
    return null;
  assert(field.data);
  return field.data;
};

ProtoReader.prototype.readFieldString = function readFieldString(tag, opt, enc) {
  var field = this.readField(tag, opt);
  if (!field)
    return null;
  assert(field.data);
  return field.data.toString(enc || 'utf8');
};

ProtoReader.prototype.nextTag = function nextTag() {
  var field;

  if (this.left() === 0)
    return -1;

  field = this.readField();

  this.seek(-field.size);

  return field.tag;
};

ProtoReader.prototype.readField = function readField(tag, opt) {
  var offset = this.offset;
  var header = this.readVarint();
  var field = new Field(header);
  var inner;

  if (tag != null && field.tag !== tag) {
    assert(opt, 'Non-optional field not present.');
    this.offset = offset;
    return null;
  }

  switch (field.type) {
    case wireType.VARINT:
      field.value = this.readVarint();
      break;
    case wireType.FIXED64:
      field.value = this.readU64();
      break;
    case wireType.DELIMITED:
      field.data = this.readVarBytes();
      break;
    case wireType.START_GROUP:
      field.group = [];
      for (;;) {
        inner = this.readField();
        if (inner.type === wireType.END_GROUP)
          break;
        field.group.push(inner);
      }
      break;
    case wireType.END_GROUP:
      assert(false, 'Unexpected end group.');
      break;
    case wireType.FIXED32:
      field.value = this.readU32();
      break;
    default:
      assert(false, 'Bad wire type.');
      break;
  }

  field.size = this.offset - offset;

  return field;
};

/**
 * ProtoWriter
 * @constructor
 */

function ProtoWriter() {
  if (!(this instanceof ProtoWriter))
    return new ProtoWriter();

  BufferWriter.call(this);
}

util.inherits(ProtoWriter, BufferWriter);

ProtoWriter.prototype.writeVarint = function writeVarint(num) {
  var size = exports.sizeVarint(num);
  var value;

  // Avoid an extra allocation until
  // we make bufferwriter more hackable.
  // More insanity here...
  switch (size) {
    case 6:
      value = exports.slipVarint(num);
      this.writeU32BE(value / 0x10000 | 0);
      this.writeU16BE(value & 0xffff);
      break;
    case 5:
      value = exports.slipVarint(num);
      this.writeU32BE(value / 0x100 | 0);
      this.writeU8(value & 0xff);
      break;
    case 4:
      value = exports.slipVarint(num);
      this.writeU32BE(value);
      break;
    case 3:
      value = exports.slipVarint(num);
      this.writeU16BE(value >> 8);
      this.writeU8(value & 0xff);
      break;
    case 2:
      value = exports.slipVarint(num);
      this.writeU16BE(value);
      break;
    case 1:
      value = exports.slipVarint(num);
      this.writeU8(value);
      break;
    default:
      value = new Buffer(size);
      exports.writeVarint(value, num, 0);
      this.writeBytes(value);
      break;
  }
};

ProtoWriter.prototype.writeFieldVarint = function writeFieldVarint(tag, value) {
  var header = (tag << 3) | wireType.VARINT;
  this.writeVarint(header);
  this.writeVarint(value);
};

ProtoWriter.prototype.writeFieldU64 = function writeFieldU64(tag, value) {
  assert(util.isSafeInteger(value));
  this.writeFieldVarint(tag, value);
};

ProtoWriter.prototype.writeFieldU32 = function writeFieldU32(tag, value) {
  assert(value <= 0xffffffff);
  this.writeFieldVarint(tag, value);
};

ProtoWriter.prototype.writeFieldBytes = function writeFieldBytes(tag, data) {
  var header = (tag << 3) | wireType.DELIMITED;
  this.writeVarint(header);
  this.writeVarint(data.length);
  this.writeBytes(data);
};

ProtoWriter.prototype.writeFieldString = function writeFieldString(tag, data, enc) {
  if (typeof data === 'string')
    data = new Buffer(data, enc || 'utf8');
  this.writeFieldBytes(tag, data);
};

/*
 * Encoding
 */

exports.readVarint = function readVarint(data, off) {
  var num = 0;
  var ch = 0x80;
  var size = 0;

  while (ch & 0x80) {
    if (off >= data.length) {
      num = 0;
      break;
    }

    ch = data[off++];

    // Optimization for javascript insanity.
    switch (size) {
      case 0:
      case 1:
      case 2:
      case 3:
        num += (ch & 0x7f) << (7 * size);
        break;
      case 4:
        num += (ch & 0x7f) * (1 << (7 * size));
        break;
      default:
        num += (ch & 0x7f) * Math.pow(2, 7 * size);
        break;
    }

    size++;

    assert(size < 7, 'Number exceeds 2^53-1.');
  }

  return new Varint(size, num);
};

exports.writeVarint = function writeVarint(data, num, off) {
  var ch;

  assert(util.isSafeInteger(num), 'Number exceeds 2^53-1.');

  do {
    assert(off < data.length);
    ch = num & 0x7f;
    num -= num % 0x80;
    num /= 0x80;
    if (num !== 0)
      ch |= 0x80;
    data[off] = ch;
    off++;
  } while (num > 0);

  return off;
};

exports.slipVarint = function slipVarint(num) {
  var data = 0;
  var size = 0;
  var ch;

  assert(util.isSafeInteger(num), 'Number exceeds 2^53-1.');

  do {
    assert(size < 7);
    ch = num & 0x7f;
    num -= num % 0x80;
    num /= 0x80;
    if (num !== 0)
      ch |= 0x80;
    data *= 256;
    data += ch;
    size++;
  } while (num > 0);

  return data;
};

exports.sizeVarint = function sizeVarint(num) {
  var size = 0;

  assert(util.isSafeInteger(num), 'Number exceeds 2^53-1.');

  do {
    num -= num % 0x80;
    num /= 0x80;
    size++;
  } while (num > 0);

  return size;
};

/*
 * Helpers
 */

function Field(header) {
  this.tag = header >>> 3;
  this.type = header & 7;
  this.size = 0;
  this.value = 0;
  this.data = null;
  this.group = null;
}

function Varint(size, value) {
  this.size = size;
  this.value = value;
}

/*
 * Expose
 */

exports.ProtoReader = ProtoReader;
exports.ProtoWriter = ProtoWriter;
