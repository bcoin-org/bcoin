/*!
 * opcode.js - opcode object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var BN = require('bn.js');
var constants = require('../protocol/constants');
var util = require('../utils/util');
var encoding = require('./encoding');
var BufferWriter = require('../utils/writer');
var assert = require('assert');
var opcodes = constants.opcodes;

/**
 * A simple struct which contains
 * an opcode and pushdata buffer.
 * @exports Opcode
 * @constructor
 * @param {Number} value - Opcode.
 * @param {Buffer?} data - Pushdata buffer.
 * @property {Number} value
 * @property {Buffer|null} data
 */

function Opcode(value, data) {
  if (!(this instanceof Opcode))
    return new Opcode(value, data);

  this.value = value;
  this.data = data || null;
}

/**
 * Encode the opcode.
 * @returns {Buffer}
 */

Opcode.prototype.toRaw = function toRaw() {
  var bw = new BufferWriter();

  if (this.value === -1)
    throw new Error('Cannot reserialize a parse error.');

  if (this.data) {
    if (this.value <= 0x4b) {
      bw.writeU8(this.data.length);
      bw.writeBytes(this.data);
    } else if (this.value === opcodes.OP_PUSHDATA1) {
      bw.writeU8(opcodes.OP_PUSHDATA1);
      bw.writeU8(this.data.length);
      bw.writeBytes(this.data);
    } else if (this.value === opcodes.OP_PUSHDATA2) {
      bw.writeU8(opcodes.OP_PUSHDATA2);
      bw.writeU16(this.data.length);
      bw.writeBytes(this.data);
    } else if (this.value === opcodes.OP_PUSHDATA4) {
      bw.writeU8(opcodes.OP_PUSHDATA4);
      bw.writeU32(this.data.length);
      bw.writeBytes(this.data);
    } else {
      throw new Error('Unknown pushdata opcode.');
    }
  } else {
    bw.writeU8(this.value);
  }

  return bw.render();
};

/**
 * Instantiate an opcode from a number opcode.
 * @param {Number} op
 * @returns {Opcode}
 */

Opcode.fromOp = function fromOp(op) {
  return new Opcode(op);
};

/**
 * Instantiate a pushdata opcode from
 * a buffer (will encode minimaldata).
 * @param {Buffer} data
 * @returns {Opcode}
 */

Opcode.fromData = function fromData(data) {
  if (data.length === 0)
    return new Opcode(opcodes.OP_0);

  if (data.length === 1) {
    if (data[0] >= 1 && data[0] <= 16)
      return new Opcode(data[0] + 0x50);

    if (data[0] === 0x81)
      return new Opcode(opcodes.OP_1NEGATE);
  }

  return Opcode.fromPush(data);
};

/**
 * Instantiate a pushdata opcode from a
 * buffer (this differs from fromData in
 * that it will _always_ be a pushdata op).
 * @param {Buffer} data
 * @returns {Opcode}
 */

Opcode.fromPush = function fromPush(data) {
  if (data.length <= 0x4b)
    return new Opcode(data.length, data);

  if (data.length <= 0xff)
    return new Opcode(opcodes.OP_PUSHDATA1, data);

  if (data.length <= 0xffff)
    return new Opcode(opcodes.OP_PUSHDATA2, data);

  if (data.length <= 0xffffffff)
    return new Opcode(opcodes.OP_PUSHDATA4, data);

  throw new Error('Pushdata size too large.');
};

/**
 * Instantiate an opcode from a Number.
 * @param {Number|BN} num
 * @returns {Opcode}
 */

Opcode.fromNumber = function fromNumber(num) {
  return Opcode.fromData(encoding.array(num));
};

/**
 * Instantiate an opcode from a small number.
 * @param {Number} num
 * @returns {Opcode}
 */

Opcode.fromSmall = function fromSmall(num) {
  assert(util.isNumber(num) && num >= 0 && num <= 16);
  return new Opcode(num === 0 ? 0 : num + 0x50);
};

/**
 * Instantiate a pushdata opcode from a string.
 * @param {String} data
 * @returns {Opcode}
 */

Opcode.fromString = function fromString(data, enc) {
  if (typeof data === 'string')
    data = new Buffer(data, enc);

  return Opcode.fromData(data);
};

/**
 * Instantiate a pushdata opcode from anything.
 * @param {String|Buffer|Number|BN|Opcode} data
 * @returns {Opcode}
 */

Opcode.from = function from(data) {
  if (data instanceof Opcode)
    return data;

  if (typeof data === 'number')
    return Opcode.fromOp(data);

  if (Buffer.isBuffer(data))
    return Opcode.fromData(data);

  if (typeof data === 'string')
    return Opcode.fromString(data, 'utf8');

  if (BN.isBN(data))
    return Opcode.fromNumber(data);

  assert(false, 'Bad data for opcode.');
};

/**
 * Test whether an object an Opcode.
 * @param {Object} obj
 * @returns {Boolean}
 */

Opcode.isOpcode = function isOpcode(obj) {
  return obj
    && typeof obj.value === 'number'
    && (Buffer.isBuffer(obj.data) || obj.data === null);
};

/*
 * Expose
 */

module.exports = Opcode;
