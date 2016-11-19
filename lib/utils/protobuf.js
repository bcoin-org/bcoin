/*!
 * protobuf.js - protobufs for bcoin
 * Copyright (c) 2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var util = require('../utils/util');
var assert = require('assert');
var BufferReader = require('../utils/reader');
var BufferWriter = require('../utils/writer');

var wireType = {
  VARINT: 0,
  FIXED64: 1,
  DELIMITED: 2,
  START_GROUP: 3,
  END_GROUP: 4,
  FIXED32: 5
};

function ProtoReader(data, zeroCopy) {
  if (data instanceof ProtoReader)
    return data;
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
  var value, data, group, field;

  if (tag != null && (header >>> 3) !== tag) {
    assert(opt, 'Non-optional field not present.');
    this.offset = offset;
    return;
  }

  switch (header & 7) {
    case wireType.VARINT:
      value = this.readVarint();
      break;
    case wireType.FIXED64:
      value = this.readU64N();
      break;
    case wireType.DELIMITED:
      data = this.readVarBytes();
      break;
    case wireType.START_GROUP:
      group = [];
      for (;;) {
        field = this.readField();
        if (field.type === wireType.END_GROUP)
          break;
        group.push(field);
      }
      break;
    case wireType.END_GROUP:
      assert(false, 'Unexpected end group.');
      break;
    case wireType.FIXED32:
      value = this.readU32();
      break;
    default:
      assert(false, 'Bad wire type.');
      break;
  }

  return {
    size: this.offset - offset,
    header: header,
    tag: header >>> 3,
    type: header & 7,
    value: value,
    data: data,
    group: group
  };
};

function ProtoWriter(options) {
  if (options instanceof ProtoWriter)
    return options;

  if (!(this instanceof ProtoWriter))
    return new ProtoWriter(options);

  BufferWriter.call(this, options);
}

util.inherits(ProtoWriter, BufferWriter);

ProtoWriter.prototype.writeVarint = function writeVarint(num) {
  var size = exports.sizeVarint(num);
  var buf = new Buffer(size);
  exports.writeVarint(buf, num, 0);
  this.writeBytes(buf);
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
  }

  assert(util.isSafeInteger(num), 'Number exceeds 2^53-1.');

  return { size: size, value: num };
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

exports.ProtoReader = ProtoReader;
exports.ProtoWriter = ProtoWriter;
