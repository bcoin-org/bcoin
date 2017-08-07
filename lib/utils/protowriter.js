/*!
 * protowriter.js - protobufs for bcoin
 * Copyright (c) 2016-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/**
 * @module utils/protobuf
 */

const assert = require('assert');
const BufferWriter = require('../utils/writer');

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
 * ProtoBuf Writer
 * @alias module:utils.ProtoWriter
 * @constructor
 */

function ProtoWriter() {
  if (!(this instanceof ProtoWriter))
    return new ProtoWriter();

  BufferWriter.call(this);
}

Object.setPrototypeOf(ProtoWriter.prototype, BufferWriter.prototype);

ProtoWriter.prototype.writeVarint = function writeVarint(num) {
  const size = sizeVarint(num);

  // Avoid an extra allocation until
  // we make bufferwriter more hackable.
  // More insanity here...
  switch (size) {
    case 6: {
      const value = slipVarint(num);
      this.writeU32BE(value / 0x10000 | 0);
      this.writeU16BE(value & 0xffff);
      break;
    }
    case 5: {
      const value = slipVarint(num);
      this.writeU32BE(value / 0x100 | 0);
      this.writeU8(value & 0xff);
      break;
    }
    case 4: {
      const value = slipVarint(num);
      this.writeU32BE(value);
      break;
    }
    case 3: {
      const value = slipVarint(num);
      this.writeU16BE(value >> 8);
      this.writeU8(value & 0xff);
      break;
    }
    case 2: {
      const value = slipVarint(num);
      this.writeU16BE(value);
      break;
    }
    case 1: {
      const value = slipVarint(num);
      this.writeU8(value);
      break;
    }
    default: {
      const value = Buffer.allocUnsafe(size);
      _writeVarint(value, num, 0);
      this.writeBytes(value);
      break;
    }
  }
};

ProtoWriter.prototype.writeFieldVarint = function writeFieldVarint(tag, value) {
  const header = (tag << 3) | wireType.VARINT;
  this.writeVarint(header);
  this.writeVarint(value);
};

ProtoWriter.prototype.writeFieldU64 = function writeFieldU64(tag, value) {
  assert(Number.isSafeInteger(value));
  this.writeFieldVarint(tag, value);
};

ProtoWriter.prototype.writeFieldU32 = function writeFieldU32(tag, value) {
  assert(value <= 0xffffffff);
  this.writeFieldVarint(tag, value);
};

ProtoWriter.prototype.writeFieldBytes = function writeFieldBytes(tag, data) {
  const header = (tag << 3) | wireType.DELIMITED;
  this.writeVarint(header);
  this.writeVarint(data.length);
  this.writeBytes(data);
};

ProtoWriter.prototype.writeFieldString = function writeFieldString(tag, data, enc) {
  if (typeof data === 'string')
    data = Buffer.from(data, enc || 'utf8');
  this.writeFieldBytes(tag, data);
};

/*
 * Encoding
 */

function _writeVarint(data, num, off) {
  assert(Number.isSafeInteger(num), 'Number exceeds 2^53-1.');

  do {
    assert(off < data.length);
    let ch = num & 0x7f;
    num -= num % 0x80;
    num /= 0x80;
    if (num !== 0)
      ch |= 0x80;
    data[off] = ch;
    off++;
  } while (num > 0);

  return off;
};

function slipVarint(num) {
  assert(Number.isSafeInteger(num), 'Number exceeds 2^53-1.');

  let data = 0;
  let size = 0;

  do {
    assert(size < 7);
    let ch = num & 0x7f;
    num -= num % 0x80;
    num /= 0x80;
    if (num !== 0)
      ch |= 0x80;
    data *= 256;
    data += ch;
    size++;
  } while (num > 0);

  return data;
}

function sizeVarint(num) {
  assert(Number.isSafeInteger(num), 'Number exceeds 2^53-1.');

  let size = 0;

  do {
    num -= num % 0x80;
    num /= 0x80;
    size++;
  } while (num > 0);

  return size;
};

/*
 * Expose
 */

module.exports = ProtoWriter;
