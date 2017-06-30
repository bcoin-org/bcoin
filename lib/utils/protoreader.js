/*!
 * protoreader.js - protobufs for bcoin
 * Copyright (c) 2016-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const util = require('../utils/util');
const BufferReader = require('../utils/reader');

/*
 * Constants
 */

const wireType = {
  VARINT: 0,
  FIXED64: 1,
  DELIMITED: 2,
  START_GROUP: 3,
  END_GROUP: 4,
  FIXED32: 5
};

/**
 * ProtoBuf Reader
 * @alias module:utils.ProtoReader
 * @constructor
 */

function ProtoReader(data, zeroCopy) {
  if (!(this instanceof ProtoReader))
    return new ProtoReader(data, zeroCopy);

  BufferReader.call(this, data, zeroCopy);
}

util.inherits(ProtoReader, BufferReader);

ProtoReader.prototype.readVarint = function _readVarint() {
  let {size, value} = readVarint(this.data, this.offset);
  this.offset += size;
  return value;
};

ProtoReader.prototype.readFieldValue = function readFieldValue(tag, opt) {
  let field = this.readField(tag, opt);
  if (!field)
    return -1;
  assert(field.value != null);
  return field.value;
};

ProtoReader.prototype.readFieldU64 = function readFieldU64(tag, opt) {
  let field = this.readField(tag, opt);
  if (!field)
    return -1;
  assert(field.type === wireType.VARINT || field.type === wireType.FIXED64);
  return field.value;
};

ProtoReader.prototype.readFieldU32 = function readFieldU32(tag, opt) {
  let field = this.readField(tag, opt);
  if (!field)
    return -1;
  assert(field.type === wireType.VARINT || field.type === wireType.FIXED32);
  return field.value;
};

ProtoReader.prototype.readFieldBytes = function readFieldBytes(tag, opt) {
  let field = this.readField(tag, opt);
  if (!field)
    return null;
  assert(field.data);
  return field.data;
};

ProtoReader.prototype.readFieldString = function readFieldString(tag, opt, enc) {
  let field = this.readField(tag, opt);
  if (!field)
    return null;
  assert(field.data);
  return field.data.toString(enc || 'utf8');
};

ProtoReader.prototype.nextTag = function nextTag() {
  let field;

  if (this.left() === 0)
    return -1;

  field = this.readField();

  this.seek(-field.size);

  return field.tag;
};

ProtoReader.prototype.readField = function readField(tag, opt) {
  let offset = this.offset;
  let header = this.readVarint();
  let field = new Field(header);
  let inner;

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

/*
 * Encoding
 */

function readVarint(data, off) {
  let num = 0;
  let ch = 0x80;
  let size = 0;

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
}

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

module.exports = ProtoReader;
