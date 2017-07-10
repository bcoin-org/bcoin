/*!
 * opcode.js - opcode object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const BN = require('../crypto/bn');
const util = require('../utils/util');
const common = require('./common');
const BufferReader = require('../utils/reader');
const StaticWriter = require('../utils/staticwriter');
const opcodes = common.opcodes;

/**
 * A simple struct which contains
 * an opcode and pushdata buffer.
 * @alias module:script.Opcode
 * @constructor
 * @param {Number} value - Opcode.
 * @param {Buffer?} data - Pushdata buffer.
 * @property {Number} value
 * @property {Buffer|null} data
 */

function Opcode(value, data) {
  if (!(this instanceof Opcode))
    return new Opcode(value, data);

  this.value = value || 0;
  this.data = data || null;
}

/**
 * Test whether a pushdata abides by minimaldata.
 * @returns {Boolean}
 */

Opcode.prototype.isMinimal = function isMinimal() {
  if (!this.data)
    return true;

  if (this.data.length === 0)
    return this.value === opcodes.OP_0;

  if (this.data.length === 1 && this.data[0] >= 1 && this.data[0] <= 16)
    return false;

  if (this.data.length === 1 && this.data[0] === 0x81)
    return false;

  if (this.data.length <= 75)
    return this.value === this.data.length;

  if (this.data.length <= 255)
    return this.value === opcodes.OP_PUSHDATA1;

  if (this.data.length <= 65535)
    return this.value === opcodes.OP_PUSHDATA2;

  return true;
};

/**
 * Test whether opcode is a disabled opcode.
 * @returns {Boolean}
 */

Opcode.prototype.isDisabled = function isDisabled() {
  switch (this.value) {
    case opcodes.OP_CAT:
    case opcodes.OP_SUBSTR:
    case opcodes.OP_LEFT:
    case opcodes.OP_RIGHT:
    case opcodes.OP_INVERT:
    case opcodes.OP_AND:
    case opcodes.OP_OR:
    case opcodes.OP_XOR:
    case opcodes.OP_2MUL:
    case opcodes.OP_2DIV:
    case opcodes.OP_MUL:
    case opcodes.OP_DIV:
    case opcodes.OP_MOD:
    case opcodes.OP_LSHIFT:
    case opcodes.OP_RSHIFT:
      return true;
  }
  return false;
};

/**
 * Test whether opcode is a branch (if/else/endif).
 * @returns {Boolean}
 */

Opcode.prototype.isBranch = function isBranch() {
  return this.value >= opcodes.OP_IF && this.value <= opcodes.OP_ENDIF;
};

/**
 * Encode the opcode to a buffer writer.
 * @param {BufferWriter} bw
 */

Opcode.prototype.toWriter = function toWriter(bw) {
  if (this.value === -1)
    throw new Error('Cannot reserialize a parse error.');

  if (!this.data) {
    bw.writeU8(this.value);
    return bw;
  }

  if (this.value <= 0x4b) {
    assert(this.value === this.data.length);
    bw.writeU8(this.value);
    bw.writeBytes(this.data);
    return bw;
  }

  switch (this.value) {
    case opcodes.OP_PUSHDATA1:
      bw.writeU8(this.value);
      bw.writeU8(this.data.length);
      bw.writeBytes(this.data);
      break;
    case opcodes.OP_PUSHDATA2:
      bw.writeU8(this.value);
      bw.writeU16(this.data.length);
      bw.writeBytes(this.data);
      break;
    case opcodes.OP_PUSHDATA4:
      bw.writeU8(this.value);
      bw.writeU32(this.data.length);
      bw.writeBytes(this.data);
      break;
    default:
      throw new Error('Unknown pushdata opcode.');
  }

  return bw;
};

/**
 * Encode the opcode.
 * @returns {Buffer}
 */

Opcode.prototype.toRaw = function toRaw() {
  let size = this.getSize();
  return this.toWriter(new StaticWriter(size)).render();
};

/**
 * Calculate opcode size.
 * @returns {Number}
 */

Opcode.prototype.getSize = function getSize() {
  if (!this.data)
    return 1;

  if (this.value <= 0x4b)
    return 1 + this.data.length;

  switch (this.value) {
    case opcodes.OP_PUSHDATA1:
      return 2 + this.data.length;
    case opcodes.OP_PUSHDATA2:
      return 3 + this.data.length;
    case opcodes.OP_PUSHDATA4:
      return 5 + this.data.length;
    default:
      throw new Error('Unknown pushdata opcode.');
  }
};

/**
 * Inject properties from buffer reader.
 * @param {BufferReader} br
 * @private
 */

Opcode.prototype.fromReader = function fromReader(br) {
  let op = br.readU8();
  let size;

  if (op >= 0x01 && op <= 0x4b) {
    if (br.left() < op) {
      this.value = -1;
      br.seek(br.left());
      return this;
    }
    this.value = op;
    this.data = br.readBytes(op);
    return this;
  }

  switch (op) {
    case opcodes.OP_PUSHDATA1:
      if (br.left() < 1) {
        this.value = -1;
        break;
      }
      size = br.readU8();
      if (br.left() < size) {
        this.value = -1;
        br.seek(br.left());
        break;
      }
      this.value = op;
      this.data = br.readBytes(size);
      break;
    case opcodes.OP_PUSHDATA2:
      if (br.left() < 2) {
        this.value = -1;
        br.seek(br.left());
        break;
      }
      size = br.readU16();
      if (br.left() < size) {
        this.value = -1;
        br.seek(br.left());
        break;
      }
      this.value = op;
      this.data = br.readBytes(size);
      break;
    case opcodes.OP_PUSHDATA4:
      if (br.left() < 4) {
        this.value = -1;
        br.seek(br.left());
        break;
      }
      size = br.readU32();
      if (br.left() < size) {
        this.value = -1;
        br.seek(br.left());
        break;
      }
      this.value = op;
      this.data = br.readBytes(size);
      break;
    default:
      this.value = op;
      break;
  }

  return this;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 * @returns {Opcode}
 */

Opcode.prototype.fromRaw = function fromRaw(data) {
  return this.fromReader(new BufferReader(data));
};

/**
 * Instantiate opcode from buffer reader.
 * @param {BufferReader} br
 * @returns {Opcode}
 */

Opcode.fromReader = function fromReader(br) {
  return new Opcode(0, null).fromReader(br);
};

/**
 * Instantiate opcode from serialized data.
 * @param {Buffer} data
 * @returns {Opcode}
 */

Opcode.fromRaw = function fromRaw(data) {
  return new Opcode(0, null).fromRaw(data);
};

/**
 * Instantiate an opcode from a number opcode.
 * @param {Number} op
 * @returns {Opcode}
 */

Opcode.fromOp = function fromOp(op) {
  return new Opcode(op, null);
};

/**
 * Instantiate a pushdata opcode from
 * a buffer (will encode minimaldata).
 * @param {Buffer} data
 * @returns {Opcode}
 */

Opcode.fromData = function fromData(data) {
  if (data.length === 0)
    return Opcode.fromOp(opcodes.OP_0);

  if (data.length === 1) {
    if (data[0] >= 1 && data[0] <= 16)
      return Opcode.fromOp(data[0] + 0x50);

    if (data[0] === 0x81)
      return Opcode.fromOp(opcodes.OP_1NEGATE);
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
  return Opcode.fromData(common.array(num));
};

/**
 * Instantiate an opcode from a small number.
 * @param {Number} num
 * @returns {Opcode}
 */

Opcode.fromSmall = function fromSmall(num) {
  assert(util.isNumber(num) && num >= 0 && num <= 16);
  return Opcode.fromOp(num === 0 ? 0 : num + 0x50);
};

/**
 * Instantiate a pushdata opcode from a string.
 * @param {String} data
 * @returns {Opcode}
 */

Opcode.fromString = function fromString(data, enc) {
  if (typeof data === 'string')
    data = Buffer.from(data, enc);

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
 * Instantiate a pushdata opcode from symbolic name.
 * @example
 *   Opcode.fromSymbol('checksequenceverify')
 * @param {String} name
 * @returns {Opcode}
 */

Opcode.fromSymbol = function fromSymbol(name) {
  let op;

  assert(typeof name === 'string');
  assert(name.length > 0);

  if (!util.isUpperCase(name))
    name = name.toUpperCase();

  if (!util.startsWith(name, 'OP_'))
    name = `OP_${name}`;

  op = common.opcodes[name];
  assert(op != null, 'Unknown opcode.');

  return Opcode.fromOp(op);
};

/**
 * Convert opcode to its symbolic representation.
 * @returns {String}
 */

Opcode.prototype.toSymbol = function toSymbol() {
  let op = this.value;
  let symbol;

  if (op === -1)
    op = 0xff;

  symbol = common.opcodesByVal[op];

  if (symbol == null)
    symbol = util.hex8(op);

  return symbol;
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
