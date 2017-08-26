/*!
 * opcode.js - opcode object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const ScriptNum = require('./scriptnum');
const util = require('../utils/util');
const common = require('./common');
const BufferReader = require('../utils/reader');
const StaticWriter = require('../utils/staticwriter');
const opcodes = common.opcodes;

const opCache = [];

let PARSE_ERROR = null;

/**
 * A simple struct which contains
 * an opcode and pushdata buffer.
 * Note: this should not be called directly.
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

  if (this.data.length === 1) {
    if (this.data[0] === 0x81)
      return false;

    if (this.data[0] >= 1 && this.data[0] <= 16)
      return false;
  }

  if (this.data.length <= 0x4b)
    return this.value === this.data.length;

  if (this.data.length <= 0xff)
    return this.value === opcodes.OP_PUSHDATA1;

  if (this.data.length <= 0xffff)
    return this.value === opcodes.OP_PUSHDATA2;

  assert(this.value === opcodes.OP_PUSHDATA4);

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
 * Test opcode equality.
 * @param {Opcode} op
 * @returns {Boolean}
 */

Opcode.prototype.equals = function equals(op) {
  assert(Opcode.isOpcode(op));

  if (this.value !== op.value)
    return false;

  if (!this.data) {
    assert(!op.data);
    return true;
  }

  assert(op.data);

  return this.data.equals(op.data);
};

/**
 * Convert Opcode to opcode value.
 * @returns {Number}
 */

Opcode.prototype.toOp = function toOp() {
  return this.value;
};

/**
 * Covert opcode to data push.
 * @returns {Buffer|null}
 */

Opcode.prototype.toData = function toData() {
  return this.data;
};

/**
 * Covert opcode to data length.
 * @returns {Number}
 */

Opcode.prototype.toLength = function toLength() {
  return this.data ? this.data.length : -1;
};

/**
 * Covert and _cast_ opcode to data push.
 * @returns {Buffer|null}
 */

Opcode.prototype.toPush = function toPush() {
  if (this.value === opcodes.OP_0)
    return common.small[0 + 1];

  if (this.value === opcodes.OP_1NEGATE)
    return common.small[-1 + 1];

  if (this.value >= opcodes.OP_1 && this.value <= opcodes.OP_16)
    return common.small[this.value - 0x50 + 1];

  return this.toData();
};

/**
 * Get string for opcode.
 * @param {String?} enc
 * @returns {Buffer|null}
 */

Opcode.prototype.toString = function toString(enc) {
  const data = this.toPush();

  if (!data)
    return null;

  return data.toString(enc || 'utf8');
};

/**
 * Convert opcode to small integer.
 * @returns {Number}
 */

Opcode.prototype.toSmall = function toSmall() {
  if (this.value === opcodes.OP_0)
    return 0;

  if (this.value >= opcodes.OP_1 && this.value <= opcodes.OP_16)
    return this.value - 0x50;

  return -1;
};

/**
 * Convert opcode to script number.
 * @param {Boolean?} minimal
 * @param {Number?} limit
 * @returns {ScriptNum|null}
 */

Opcode.prototype.toNum = function toNum(minimal, limit) {
  if (this.value === opcodes.OP_0)
    return ScriptNum.fromInt(0);

  if (this.value === opcodes.OP_1NEGATE)
    return ScriptNum.fromInt(-1);

  if (this.value >= opcodes.OP_1 && this.value <= opcodes.OP_16)
    return ScriptNum.fromInt(this.value - 0x50);

  if (!this.data)
    return null;

  return ScriptNum.decode(this.data, minimal, limit);
};

/**
 * Convert opcode to integer.
 * @param {Boolean?} minimal
 * @param {Number?} limit
 * @returns {Number}
 */

Opcode.prototype.toInt = function toInt(minimal, limit) {
  const num = this.toNum(minimal, limit);

  if (!num)
    return -1;

  return num.getInt();
};

/**
 * Convert opcode to boolean.
 * @returns {Boolean}
 */

Opcode.prototype.toBool = function toBool() {
  const smi = this.toSmall();

  if (smi === -1)
    return false;

  return smi === 1;
};

/**
 * Convert opcode to its symbolic representation.
 * @returns {String}
 */

Opcode.prototype.toSymbol = function toSymbol() {
  if (this.value === -1)
    return 'OP_INVALIDOPCODE';

  const symbol = common.opcodesByVal[this.value];

  if (!symbol)
    return `0x${util.hex8(this.value)}`;

  return symbol;
};

/**
 * Calculate opcode size.
 * @returns {Number}
 */

Opcode.prototype.getSize = function getSize() {
  if (!this.data)
    return 1;

  switch (this.value) {
    case opcodes.OP_PUSHDATA1:
      return 2 + this.data.length;
    case opcodes.OP_PUSHDATA2:
      return 3 + this.data.length;
    case opcodes.OP_PUSHDATA4:
      return 5 + this.data.length;
    default:
      return 1 + this.data.length;
  }
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
      assert(this.value === this.data.length);
      bw.writeU8(this.value);
      bw.writeBytes(this.data);
      break;
  }

  return bw;
};

/**
 * Encode the opcode.
 * @returns {Buffer}
 */

Opcode.prototype.toRaw = function toRaw() {
  const size = this.getSize();
  return this.toWriter(new StaticWriter(size)).render();
};

/**
 * Convert the opcode to a bitcoind test string.
 * @returns {String} Human-readable script code.
 */

Opcode.prototype.toFormat = function toFormat() {
  if (this.value === -1)
    return '0x01';

  if (this.data) {
    // Numbers
    if (this.data.length <= 4) {
      const num = this.toNum();
      if (this.equals(Opcode.fromNum(num)))
        return num.toString(10);
    }

    const symbol = common.opcodesByVal[this.value];
    const data = this.data.toString('hex');

    // Direct push
    if (!symbol) {
      const size = util.hex8(this.value);
      return `0x${size} 0x${data}`;
    }

    // Pushdatas
    let size = this.data.length.toString(16);

    while (size.length % 2 !== 0)
      size = '0' + size;

    return `${symbol} 0x${size} 0x${data}`;
  }

  // Opcodes
  const symbol = common.opcodesByVal[this.value];
  if (symbol)
    return symbol;

  // Unknown opcodes
  const value = util.hex8(this.value);

  return `0x${value}`;
};

/**
 * Format the opcode as bitcoind asm.
 * @param {Boolean?} decode - Attempt to decode hash types.
 * @returns {String} Human-readable script.
 */

Opcode.prototype.toASM = function toASM(decode) {
  if (this.value === -1)
    return '[error]';

  if (this.data)
    return common.toASM(this.data, decode);

  return common.opcodesByVal[this.value] || 'OP_UNKNOWN';
};

/**
 * Instantiate an opcode from a number opcode.
 * @param {Number} op
 * @returns {Opcode}
 */

Opcode.fromOp = function fromOp(op) {
  assert(typeof op === 'number');

  const cached = opCache[op];

  assert(cached, 'Bad opcode.');

  return cached;
};

/**
 * Instantiate a pushdata opcode from
 * a buffer (will encode minimaldata).
 * @param {Buffer} data
 * @returns {Opcode}
 */

Opcode.fromData = function fromData(data) {
  assert(Buffer.isBuffer(data));

  if (data.length === 1) {
    if (data[0] === 0x81)
      return Opcode.fromOp(opcodes.OP_1NEGATE);

    if (data[0] >= 1 && data[0] <= 16)
      return Opcode.fromOp(data[0] + 0x50);
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
  assert(Buffer.isBuffer(data));

  if (data.length === 0)
    return Opcode.fromOp(opcodes.OP_0);

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
 * Instantiate a pushdata opcode from a string.
 * @param {String} str
 * @param {String} [enc=utf8]
 * @returns {Opcode}
 */

Opcode.fromString = function fromString(str, enc) {
  assert(typeof str === 'string');
  const data = Buffer.from(str, enc || 'utf8');
  return Opcode.fromData(data);
};

/**
 * Instantiate an opcode from a small number.
 * @param {Number} num
 * @returns {Opcode}
 */

Opcode.fromSmall = function fromSmall(num) {
  assert(util.isU8(num) && num >= 0 && num <= 16);
  return Opcode.fromOp(num === 0 ? 0 : num + 0x50);
};

/**
 * Instantiate an opcode from a ScriptNum.
 * @param {ScriptNumber} num
 * @returns {Opcode}
 */

Opcode.fromNum = function fromNum(num) {
  assert(ScriptNum.isScriptNum(num));
  return Opcode.fromData(num.encode());
};

/**
 * Instantiate an opcode from a Number.
 * @param {Number} num
 * @returns {Opcode}
 */

Opcode.fromInt = function fromInt(num) {
  assert(util.isInt(num));

  if (num === 0)
    return Opcode.fromOp(opcodes.OP_0);

  if (num === -1)
    return Opcode.fromOp(opcodes.OP_1NEGATE);

  if (num >= 1 && num <= 16)
    return Opcode.fromOp(num + 0x50);

  return Opcode.fromNum(ScriptNum.fromNumber(num));
};

/**
 * Instantiate an opcode from a Number.
 * @param {Boolean} value
 * @returns {Opcode}
 */

Opcode.fromBool = function fromBool(value) {
  assert(typeof value === 'boolean');
  return Opcode.fromSmall(value ? 1 : 0);
};

/**
 * Instantiate a pushdata opcode from symbolic name.
 * @example
 *   Opcode.fromSymbol('checksequenceverify')
 * @param {String} name
 * @returns {Opcode}
 */

Opcode.fromSymbol = function fromSymbol(name) {
  assert(typeof name === 'string');
  assert(name.length > 0);

  if (!util.isUpperCase(name))
    name = name.toUpperCase();

  if (!util.startsWith(name, 'OP_'))
    name = `OP_${name}`;

  const op = common.opcodes[name];

  if (op != null)
    return Opcode.fromOp(op);

  assert(util.startsWith(name, 'OP_0X'), 'Unknown opcode.');
  assert(name.length === 7, 'Unknown opcode.');

  const value = parseInt(name.substring(5), 16);

  assert(util.isU8(value), 'Unknown opcode.');

  return Opcode.fromOp(value);
};

/**
 * Instantiate opcode from buffer reader.
 * @param {BufferReader} br
 * @returns {Opcode}
 */

Opcode.fromReader = function fromReader(br) {
  const value = br.readU8();
  const op = opCache[value];

  if (op)
    return op;

  switch (value) {
    case opcodes.OP_PUSHDATA1: {
      if (br.left() < 1)
        return PARSE_ERROR;

      const size = br.readU8();

      if (br.left() < size) {
        br.seek(br.left());
        return PARSE_ERROR;
      }

      const data = br.readBytes(size);

      return new Opcode(value, data);
    }
    case opcodes.OP_PUSHDATA2: {
      if (br.left() < 2) {
        br.seek(br.left());
        return PARSE_ERROR;
      }

      const size = br.readU16();

      if (br.left() < size) {
        br.seek(br.left());
        return PARSE_ERROR;
      }

      const data = br.readBytes(size);

      return new Opcode(value, data);
    }
    case opcodes.OP_PUSHDATA4: {
      if (br.left() < 4) {
        br.seek(br.left());
        return PARSE_ERROR;
      }

      const size = br.readU32();

      if (br.left() < size) {
        br.seek(br.left());
        return PARSE_ERROR;
      }

      const data = br.readBytes(size);

      return new Opcode(value, data);
    }
    default: {
      if (br.left() < value) {
        br.seek(br.left());
        return PARSE_ERROR;
      }

      const data = br.readBytes(value);

      return new Opcode(value, data);
    }
  }
};

/**
 * Instantiate opcode from serialized data.
 * @param {Buffer} data
 * @returns {Opcode}
 */

Opcode.fromRaw = function fromRaw(data) {
  return Opcode.fromReader(new BufferReader(data));
};

/**
 * Test whether an object an Opcode.
 * @param {Object} obj
 * @returns {Boolean}
 */

Opcode.isOpcode = function isOpcode(obj) {
  return obj instanceof Opcode;
};

/*
 * Fill Cache
 */

PARSE_ERROR = Object.freeze(new Opcode(-1));

for (let value = 0x00; value <= 0xff; value++) {
  if (value >= 0x01 && value <= 0x4e) {
    opCache.push(null);
    continue;
  }
  const op = new Opcode(value);
  opCache.push(Object.freeze(op));
}

/*
 * Expose
 */

module.exports = Opcode;
