/*!
 * script.js - script interpreter for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var bcoin = require('./env');
var bn = require('bn.js');
var constants = bcoin.protocol.constants;
var utils = require('./utils');
var assert = utils.assert;
var BufferWriter = require('./writer');
var BufferReader = require('./reader');
var opcodes = constants.opcodes;
var STACK_TRUE = new Buffer([1]);
var STACK_FALSE = new Buffer([]);
var STACK_NEGATE = new Buffer([0x81]);
var ScriptError = bcoin.errors.ScriptError;

/**
 * Refers to the witness field of segregated witness transactions.
 * @exports Witness
 * @constructor
 * @param {Buffer[]|Buffer|NakedWitness} items - Array of
 * stack items or raw witness buffer.
 * @property {Buffer[]} items
 * @property {Script?} redeem
 * @property {Number} length
 */

function Witness(items) {
  if (!(this instanceof Witness))
    return new Witness(items);

  if (!items)
    items = [];

  if (items.items)
    items = items.items;

  this.items = items;

  this.redeem = null;

  assert(Array.isArray(this.items));
}

Witness.prototype.toArray = function toArray() {
  return this.items.slice();
};

Witness.fromArray = function fromArray(items) {
  return new Witness(items);
};

/**
 * Inspect a Witness object.
 * @returns {String} Human-readable script.
 */

Witness.prototype.inspect = function inspect() {
  return '<Witness: ' + this.toString() + '>';
};

/**
 * Convert a Witness object to a String.
 * @returns {String} Human-readable script.
 */

Witness.prototype.toString = function toString() {
  return Witness.format(this.items);
};

/**
 * Format the witness object as bitcoind asm.
 * @param {Boolean?} decode - Attempt to decode hash types.
 * @returns {String} Human-readable script.
 */

Witness.prototype.toASM = function toASM(decode) {
  return Script.formatASM(Script.parseArray(this.items), decode);
};

/**
 * Clone the witness object. Note that the raw
 * encoded witness data will be lost. This is
 * because the function assumes you are going
 * to be altering the stack items by hand.
 * @returns {Witness} A clone of the current witness object.
 */

Witness.prototype.clone = function clone() {
  return new Witness(this.items.slice());
};

/**
 * Convert the Witness to a Stack object.
 * This is usually done before executing
 * a witness program.
 * @returns {Stack}
 */

Witness.prototype.toStack = function toStack() {
  return new Stack(this.items.slice());
};

/**
 * "Guess" the type of the witness.
 * This method is not 100% reliable.
 * @returns {String}
 */

Witness.prototype.getInputType = function getInputType() {
  return (this.isPubkeyhashInput() && 'witnesspubkeyhash')
    || (this.isScripthashInput() && 'witnessscripthash')
    || 'unknown';
};

/**
 * "Guess" the address of the witness.
 * This method is not 100% reliable.
 * @returns {String|null}
 */

Witness.prototype.getInputAddress = function getInputAddress() {
  return bcoin.address.fromWitness(this);
};

/**
 * "Test" whether the witness is a pubkey input.
 * Always returns false.
 * @returns {Boolean}
 */

Witness.prototype.isPubkeyInput = function isPubkeyInput() {
  return false;
};

/**
 * "Guess" whether the witness is a pubkeyhash input.
 * This method is not 100% reliable.
 * @returns {Boolean}
 */

Witness.prototype.isPubkeyhashInput = function isPubkeyhashInput() {
  return this.items.length === 2
    && Script.isSignatureEncoding(this.items[0])
    && Script.isKeyEncoding(this.items[1]);
};

/**
 * "Test" whether the witness is a multisig input.
 * Always returns false.
 * @returns {Boolean}
 */

Witness.prototype.isMultisigInput = function isMultisigInput() {
  return false;
};

/**
 * "Guess" whether the witness is a scripthash input.
 * This method is not 100% reliable.
 * @returns {Boolean}
 */

Witness.prototype.isScripthashInput = function isScripthashInput() {
  return this.items.length > 0 && !this.isPubkeyhashInput();
};

/**
 * "Guess" whether the witness is an unknown/non-standard type.
 * This method is not 100% reliable.
 * @returns {Boolean}
 */

Witness.prototype.isUnknownInput = function isUnknownInput() {
  return this.getInputType() === 'unknown';
};

/**
 * Test the witness against a bloom filter.
 * @param {Bloom} filter
 * @returns {Boolean}
 */

Witness.prototype.test = function test(filter) {
  var i, chunk;

  for (i = 0; i < this.items.length; i++) {
    chunk = this.items[i];

    if (chunk.length === 0)
      continue;

    if (filter.test(chunk))
      return true;
  }

  return false;
};

/**
 * Grab and deserialize the redeem script from the witness.
 * @returns {Script} Redeem script.
 */

Witness.prototype.getRedeem = function getRedeem() {
  var redeem;

  if (!this.redeem) {
    redeem = this.items[this.items.length - 1];

    if (!redeem)
      return;

    this.redeem = new Script(redeem);
  }

  return this.redeem;
};

/**
 * Does nothing currently.
 */

Witness.prototype.compile = function compile() {
  // NOP
};

/**
 * Find a data element in a witness.
 * @param {Buffer} data - Data element to match against.
 * @returns {Number} Index (`-1` if not present).
 */

Witness.prototype.indexOf = function indexOf(data) {
  return utils.indexOf(this.items, data);
};

/**
 * Encode the witness to a Buffer.
 * @param {String} enc - Encoding, either `'hex'` or `null`.
 * @returns {Buffer|String} Serialized script.
 */

Witness.prototype.toRaw = function toRaw(enc) {
  var data = bcoin.protocol.framer.witness(this);
  if (enc === 'hex')
    data = data.toString('hex');
  return data;
};

/**
 * Unshift an item onto the witness vector.
 * @param {Number|String|Buffer|BN} data
 * @returns {Number}
 */

Witness.prototype.unshift = function unshift(data) {
  return this.items.unshift(Witness.encodeItem(data));
};

/**
 * Push an item onto the witness vector.
 * @param {Number|String|Buffer|BN} data
 * @returns {Number}
 */

Witness.prototype.push = function push(data) {
  return this.items.push(Witness.encodeItem(data));
};

/**
 * Shift an item off the witness vector.
 * @returns {Buffer}
 */

Witness.prototype.shift = function shift() {
  return this.items.shift();
};

/**
 * Shift an item off the witness vector.
 * @returns {Buffer}
 */

Witness.prototype.pop = function push(data) {
  return this.items.pop();
};

/**
 * Remove an item from the witness vector.
 * @param {Number} index
 * @returns {Buffer}
 */

Witness.prototype.remove = function remove(i) {
  return this.items.splice(i, 1)[0];
};

/**
 * Insert an item into the witness vector.
 * @param {Number} index
 * @param {Number|String|Buffer|BN} data
 */

Witness.prototype.insert = function insert(i, data) {
  assert(i <= this.items.length, 'Index out of bounds.');
  this.items.splice(i, 0, Witness.encodeItem(data))[0];
};

/**
 * Get an item from the witness vector.
 * @param {Number} index
 * @returns {Buffer}
 */

Witness.prototype.get = function get(i) {
  return this.items[i];
};

/**
 * Get a small int (0-16) from the witness vector.
 * @param {Number} index
 * @returns {Number} `-1` on non-existent.
 */

Witness.prototype.getSmall = function getSmall(i) {
  var item = this.items[i];
  if (!item || item.length > 1)
    return -1;
  if (item.length === 0)
    return 0;
  if (!(item[0] >= 1 && item[1] <= 16))
    return -1;
  return item[0];
};

/**
 * Get a number from the witness vector.
 * @param {Number} index
 * @returns {BN}
 */

Witness.prototype.getNumber = function getNumber(i) {
  var item = this.items[i];
  if (!item || item.length > 5)
    return;
  return Script.num(item, constants.flags.VERIFY_NONE, 5);
};

/**
 * Get a string from the witness vector.
 * @param {Number} index
 * @returns {String}
 */

Witness.prototype.getString = function getString(i) {
  var item = this.items[i];
  if (!item)
    return;
  return item.toString('utf8');
};

/**
 * Set an item in the witness vector.
 * @param {Number} index
 * @param {Number|String|Buffer|BN} data
 */

Witness.prototype.set = function set(i, data) {
  assert(i <= this.items.length, 'Index out of bounds.');
  this.items[i] = Witness.encodeItem(data);
};

Witness.prototype.__defineGetter__('length', function() {
  return this.items.length;
});

Witness.prototype.__defineSetter__('length', function(len) {
  return this.items.length = len;
});

/**
 * Encode a witness item.
 * @param {Number|String|Buffer|BN} data
 * @returns {Buffer}
 */

Witness.encodeItem = function encodeItem(data) {
  if (data instanceof Opcode)
    data = data.data || data.value;

  if (typeof data === 'number') {
    if (data === opcodes.OP_1NEGATE)
      return STACK_NEGATE;

    if (data === opcodes.OP_0)
      return STACK_FALSE;

    if (data >= opcodes.OP_1 && data <= opcodes.OP_16)
      return new Buffer([data - 0x50]);

    throw new Error('Non-push opcode in witness.');
  }

  if (bn.isBN(data))
    return Script.array(data);

  if (typeof data === 'string')
    return new Buffer(data, 'utf8');

  return data;
};

/**
 * Create a witness from a serialized buffer.
 * @param {Buffer|String} data - Serialized witness.
 * @param {String?} enc - Either `"hex"` or `null`.
 * @returns {Object} Naked witness object.
 */

Witness.parseRaw = function parseRaw(data, enc) {
  if (enc === 'hex')
    data = new Buffer(data, 'hex');

  return bcoin.protocol.parser.parseWitness(data);
};

/**
 * Create a Witness from a serialized buffer.
 * @param {Buffer|String} data - Serialized witness.
 * @param {String?} enc - Either `"hex"` or `null`.
 * @returns {Witness}
 */

Witness.fromRaw = function fromRaw(data, enc) {
  return new Witness(Witness.parseRaw(data, enc));
};

/**
 * Parse a test script/array
 * string into a witness object. _Must_
 * contain only stack items (no non-push
 * opcodes).
 * @param {String|String[]} items - Script string.
 * @returns {Witness}
 * @throws Parse error.
 */

Witness.fromString = function fromString(items) {
  var i, result;

  if (!Array.isArray(items)) {
    if (typeof items !== 'string')
      return new Witness();

    items = items.trim().split(/\s+/);
  }

  if (items.length === 0)
    return new Witness();

  result = new Array(items.length);

  for (i = 0; i < items.length; i++)
    result[i] = new Buffer(items[i], 'hex');

  return new Witness(result);
};

/**
 * Format script code into a human readable-string.
 * @param {Array} code
 * @returns {String} Human-readable string.
 */

Witness.format = function format(items) {
  return items.map(function(chunk) {
    return chunk.toString('hex');
  }).join(' ');
};

/**
 * Test an object to see if it is a Witness.
 * @param {Object} obj
 * @returns {Boolean}
 */

Witness.isWitness = function isWitness(obj) {
  return obj
    && Array.isArray(obj.items)
    && typeof obj.toStack === 'function';
};

/**
 * Represents the stack of a Script during execution.
 * @exports Stack
 * @constructor
 * @param {Buffer[]?} items - Stack items.
 * @property {Buffer[]} items - Stack items.
 * @property {Number} length - Size of stack.
 */

function Stack(items) {
  if (!(this instanceof Stack))
    return new Stack(items);

  this.items = items || [];
}

/**
 * Inspect the stack.
 * @returns {String} Human-readable stack.
 */

Stack.prototype.inspect = function inspect() {
  return '<Stack: ' + this.toString() + '>';
};

/**
 * Convert the stack to a string.
 * @returns {String} Human-readable stack.
 */

Stack.prototype.toString = function toString() {
  return Witness.format(this.items);
};

/**
 * Format the stack as bitcoind asm.
 * @param {Boolean?} decode - Attempt to decode hash types.
 * @returns {String} Human-readable script.
 */

Stack.prototype.toASM = function toASM(decode) {
  return Script.formatASM(this.items, decode);
};

Stack.prototype.__defineGetter__('length', function() {
  return this.items.length;
});

Stack.prototype.__defineSetter__('length', function(value) {
  return this.items.length = value;
});

/**
 * Pop the redeem script off the stack and deserialize it.
 * @returns {Script|null} The redeem script.
 */

Stack.prototype.getRedeem = function getRedeem() {
  var redeem = this.items[this.items.length - 1];
  if (!redeem)
    return;
  return new Script(redeem);
};

/**
 * Clone the stack.
 * @returns {Stack} Cloned stack.
 */

Stack.prototype.clone = function clone() {
  return new Stack(this.items.slice());
};

/**
 * Get total size of the stack, including the alt stack.
 * @param {Array} alt - Alt stack.
 * @returns {Number}
 */

Stack.prototype.getSize = function getSize(alt) {
  return this.items.length + alt.length;
};

/**
 * Push item onto stack.
 * @see Array#push
 * @param {Buffer} item
 * @returns {Number} Stack size.
 */

Stack.prototype.push = function push(item) {
  return this.items.push(item);
};

/**
 * Unshift item from stack.
 * @see Array#unshift
 * @param {Buffer} item
 * @returns {Number}
 */

Stack.prototype.unshift = function unshift(item) {
  return this.items.unshift(item);
};

/**
 * Slice out part of the stack items.
 * @param {Number} start
 * @param {Number} end
 * @see Array#slice
 * @returns {Buffer[]}
 */

Stack.prototype.slice = function slice(start, end) {
  return this.items.slice(start, end);
};

/**
 * Splice stack items.
 * @see Array#splice
 * @param {Number} index
 * @param {Number} remove
 * @param {Buffer?} insert
 * @returns {Buffer[]}
 */

Stack.prototype.splice = function splice(i, remove, insert) {
  if (insert === undefined)
    return this.items.splice(i, remove);
  return this.items.splice(i, remove, insert);
};

/**
 * Pop a stack item.
 * @see Array#pop
 * @returns {Buffer|null}
 */

Stack.prototype.pop = function pop() {
  return this.items.pop();
};

/**
 * Shift a stack item.
 * @see Array#shift
 * @returns {Buffer|null}
 */

Stack.prototype.shift = function shift() {
  return this.items.shift();
};

/**
 * Get a stack item by index.
 * @param {Number} index
 * @returns {Buffer|null}
 */

Stack.prototype.get = function get(i) {
  return this.items[i];
};

/**
 * Get a stack item relative to
 * the top of the stack.
 * @example
 * stack.top(-1);
 * @param {Number} index
 * @returns {Buffer|null}
 */

Stack.prototype.top = function top(i) {
  return this.items[this.items.length + i];
};

/**
 * Set stack item at index.
 * @param {Number} index
 * @param {Buffer} value
 * @returns {Buffer}
 */

Stack.prototype.set = function set(i, value) {
  return this.items[i] = value;
};

Stack.prototype._swap = function _swap(i1, i2) {
  var v1, v2;

  i1 = this.items.length + i1;
  i2 = this.items.length + i2;

  v1 = this.items[i1];
  v2 = this.items[i2];

  this.items[i1] = v2;
  this.items[i2] = v1;
};

/**
 * Perform the OP_TOALTSTACK operation.
 * @param {Array} alt - Alt stack.
 * @throws {ScriptError}
 */


Stack.prototype.toalt = function toalt(alt) {
  if (this.length === 0)
    throw new ScriptError('INVALID_STACK_OPERATION', opcodes.OP_TOALTSTACK);

  alt.push(this.pop());
};

/**
 * Perform the OP_FROMALTSTACK operation.
 * @param {Array} alt - Alt stack.
 * @throws {ScriptError}
 */

Stack.prototype.fromalt = function fromalt(alt) {
  if (alt.length === 0)
    throw new ScriptError('INVALID_ALTSTACK_OPERATION', opcodes.OP_FROMALTSTACK);

  this.push(alt.pop());
};

/**
 * Perform the OP_IFDUP operation.
 * @throws {ScriptError}
 */

Stack.prototype.ifdup = function ifdup() {
  if (this.length === 0)
    throw new ScriptError('INVALID_STACK_OPERATION', opcodes.OP_IFDUP);

  if (Script.bool(this.top(-1)))
    this.push(Script.array(this.top(-1)));
};

/**
 * Perform the OP_DEPTH operation.
 * @throws {ScriptError}
 */

Stack.prototype.depth = function depth() {
  this.push(Script.array(this.length));
};

/**
 * Perform the OP_DROP operation.
 * @throws {ScriptError}
 */

Stack.prototype.drop = function drop() {
  if (this.length === 0)
    throw new ScriptError('INVALID_STACK_OPERATION', opcodes.OP_DROP);

  this.pop();
};

/**
 * Perform the OP_DUP operation.
 * @throws {ScriptError}
 */

Stack.prototype.dup = function dup() {
  if (this.length === 0)
    throw new ScriptError('INVALID_STACK_OPERATION', opcodes.OP_DUP);

  this.push(this.top(-1));
};

/**
 * Perform the OP_NIP operation.
 * @throws {ScriptError}
 */

Stack.prototype.nip = function nip() {
  if (this.length < 2)
    throw new ScriptError('INVALID_STACK_OPERATION', opcodes.OP_NIP);

  this.splice(this.length - 2, 1);
};

/**
 * Perform the OP_OVER operation.
 * @throws {ScriptError}
 */

Stack.prototype.over = function over() {
  if (this.length < 2)
    throw new ScriptError('INVALID_STACK_OPERATION', opcodes.OP_OVER);

  this.push(this.top(-2));
};

/**
 * Perform the OP_PICK operation.
 * @param {VerifyFlags} flags
 * @throws {ScriptError}
 */

Stack.prototype.pick = function pick(flags) {
  return this._pickroll(opcodes.OP_PICK, flags);
};

/**
 * Perform the OP_ROLL operation.
 * @param {VerifyFlags} flags
 * @throws {ScriptError}
 */

Stack.prototype.roll = function roll(flags) {
  return this._pickroll(opcodes.OP_ROLL, flags);
};

Stack.prototype._pickroll = function pickroll(op, flags) {
  var val, n;

  if (this.length < 2)
    throw new ScriptError('INVALID_STACK_OPERATION', op);

  val = this.pop();
  n = Script.num(val, flags).toNumber();

  if (n < 0 || n >= this.length)
    throw new ScriptError('INVALID_STACK_OPERATION', op);

  val = this.top(-n - 1);

  if (op === opcodes.OP_ROLL)
    this.splice(this.length - n - 1, 1);

  this.push(val);
};

/**
 * Perform the OP_ROT operation.
 * @throws {ScriptError}
 */

Stack.prototype.rot = function rot() {
  if (this.length < 3)
    throw new ScriptError('INVALID_STACK_OPERATION', opcodes.OP_ROT);

  this._swap(-3, -2);
  this._swap(-2, -1);
};

/**
 * Perform the OP_SWAP operation.
 * @throws {ScriptError}
 */

Stack.prototype.swap = function swap() {
  if (this.length < 2)
    throw new ScriptError('INVALID_STACK_OPERATION', opcodes.OP_SWAP);

  this._swap(-2, -1);
};

/**
 * Perform the OP_TUCK operation.
 * @throws {ScriptError}
 */

Stack.prototype.tuck = function tuck() {
  if (this.length < 2)
    throw new ScriptError('INVALID_STACK_OPERATION', opcodes.OP_TUCK);

  this.splice(this.length - 2, 0, this.top(-1));
};

/**
 * Perform the OP_2DROP operation.
 * @throws {ScriptError}
 */

Stack.prototype.drop2 = function drop2() {
  if (this.length < 2)
    throw new ScriptError('INVALID_STACK_OPERATION', opcodes.OP_2DROP);

  this.pop();
  this.pop();
};

/**
 * Perform the OP_2DUP operation.
 * @throws {ScriptError}
 */

Stack.prototype.dup2 = function dup2() {
  var v1, v2;

  if (this.length < 2)
    throw new ScriptError('INVALID_STACK_OPERATION', opcodes.OP_2DUP);

  v1 = this.top(-2);
  v2 = this.top(-1);

  this.push(v1);
  this.push(v2);
};

/**
 * Perform the OP_3DUP operation.
 * @throws {ScriptError}
 */

Stack.prototype.dup3 = function dup3() {
  var v1, v2, v3;

  if (this.length < 3)
    throw new ScriptError('INVALID_STACK_OPERATION', opcodes.OP_3DUP);

  v1 = this.top(-3);
  v2 = this.top(-2);
  v3 = this.top(-1);

  this.push(v1);
  this.push(v2);
  this.push(v3);
};

/**
 * Perform the OP_2OVER operation.
 * @throws {ScriptError}
 */

Stack.prototype.over2 = function over2() {
  var v1, v2;

  if (this.length < 4)
    throw new ScriptError('INVALID_STACK_OPERATION', opcodes.OP_2OVER);

  v1 = this.top(-4);
  v2 = this.top(-3);

  this.push(v1);
  this.push(v2);
};

/**
 * Perform the OP_2ROT operation.
 * @throws {ScriptError}
 */

Stack.prototype.rot2 = function rot2() {
  var v1, v2;

  if (this.length < 6)
    throw new ScriptError('INVALID_STACK_OPERATION', opcodes.OP_2ROT);

  v1 = this.top(-6);
  v2 = this.top(-5);

  this.splice(this.length - 6, 2);
  this.push(v1);
  this.push(v2);
};

/**
 * Perform the OP_2SWAP operation.
 * @throws {ScriptError}
 */

Stack.prototype.swap2 = function swap2() {
  if (this.length < 4)
    throw new ScriptError('INVALID_STACK_OPERATION', opcodes.OP_2SWAP);

  this._swap(-4, -2);
  this._swap(-3, -1);
};

/**
 * Perform the OP_SIZE operation.
 * @throws {ScriptError}
 */

Stack.prototype.size = function size() {
  if (this.length < 1)
    throw new ScriptError('INVALID_STACK_OPERATION', opcodes.OP_SIZE);

  this.push(Script.array(this.top(-1).length));
};

/**
 * Test an object to see if it is a Stack.
 * @param {Object} obj
 * @returns {Boolean}
 */

Stack.isStack = function isStack(obj) {
  return obj && Array.isArray(obj.items) && typeof obj.swap2 === 'function';
};

/**
 * Represents a input or output script.
 * @exports Script
 * @constructor
 * @param {Buffer|Array|Object|NakedScript} code - Array
 * of script code or a serialized script Buffer.
 * @property {Array} code - Script code.
 * @property {Buffer?} raw - Serialized script.
 * @property {Script?} redeem - Redeem script.
 * @property {Number} length
 */

function Script(raw) {
  if (raw instanceof Script)
    return raw;

  if (!(this instanceof Script))
    return new Script(raw);

  if (!raw)
    raw = STACK_FALSE;

  if (raw.raw)
    raw = raw.raw;

  this.raw = null;
  this.code = null;
  this.redeem = null;

  if (Array.isArray(raw)) {
    raw = Script.parseArray(raw);
    this.raw = Script.encode(raw);
    this.code = raw;
  } else {
    this.raw = raw;
    this.code = Script.decode(raw);
  }

  assert(Buffer.isBuffer(this.raw));
  assert(Array.isArray(this.code));
}

/**
 * Convert the script to an array of
 * Buffers (pushdatas) and Numbers
 * (opcodes).
 * @returns {Array}
 */

Script.prototype.toArray = function toArray() {
  var code = [];
  var i, op;

  for (i = 0; i < this.code.length; i++) {
    op = this.code[i];
    code.push(op.data || op.value);
  }

  return code;
};

/**
 * Instantiate script from an array
 * of buffers and numbers.
 * @returns {Script}
 */

Script.fromArray = function fromArray(code) {
  return new Script(code);
};

/**
 * Clone the script.
 * @returns {Script} Cloned script.
 */

Script.prototype.clone = function clone() {
  return new Script(this.raw);
};

/**
 * Inspect the script.
 * @returns {String} Human-readable script code.
 */

Script.prototype.inspect = function inspect() {
  return '<Script: ' + this.toString() + '>';
};

/**
 * Convert the script to a bitcoind test string.
 * @returns {String} Human-readable script code.
 */

Script.prototype.toString = function toString() {
  return Script.format(this.code);
};

/**
 * Format the script as bitcoind asm.
 * @param {Boolean?} decode - Attempt to decode hash types.
 * @returns {String} Human-readable script.
 */

Script.prototype.toASM = function toASM(decode) {
  return Script.formatASM(this.code, decode);
};

/**
 * Encode the script to a Buffer. Note that this
 * will _not_ contain the varint size before it.
 * This allows it to be hashed for scripthashes.
 * @returns {Buffer} Serialized script.
 */

Script.prototype.encode = function encode() {
  return this.raw;
};

/**
 * Re-encode the script internally. Useful if you
 * changed something manually in the `code` array.
 */

Script.prototype.compile = function compile() {
  this.raw = Script.encode(this.code);
};

/**
 * Encode the script to a Buffer. See {@link Script#encode}.
 * @param {String} enc - Encoding, either `'hex'` or `null`.
 * @returns {Buffer|String} Serialized script.
 */

Script.prototype.toRaw = function toRaw(enc) {
  var data = this.encode();
  if (enc === 'hex')
    data = data.toString('hex');
  return data;
};

/**
 * Get the script's "subscript" starting at a separator.
 * @param {Number?} lastSep - The last separator to sign/verify beyond.
 * @returns {Script} Subscript.
 */

Script.prototype.getSubscript = function getSubscript(lastSep) {
  var code = [];
  var i, op;

  if (lastSep === 0)
    return this.clone();

  for (i = lastSep; i < this.code.length; i++) {
    op = this.code[i];
    if (op.value === -1)
      break;
    code.push(op);
  }

  return new Script(code);
};

/**
 * Get the script's "subscript" starting at a separator.
 * Remove all OP_CODESEPARATORs if present. This bizarre
 * behavior is necessary for signing and verification when
 * code separators are present.
 * @returns {Script} Subscript.
 */

Script.prototype.removeSeparators = function removeSeparators() {
  var code = [];
  var i, op;

  for (i = 0; i < this.code.length; i++) {
    op = this.code[i];
    if (op.value === -1)
      break;
    if (op.value !== opcodes.OP_CODESEPARATOR)
      code.push(op);
  }

  if (code.length === this.code.length)
    return this.clone();

  return new Script(code);
};

/**
 * Execute and interpret the script.
 * @param {Stack} stack - Script execution stack.
 * @param {Number?} flags - Script standard flags.
 * @param {TX?} tx - Transaction being verified.
 * @param {Number?} index - Index of input being verified.
 * @param {Number?} version - Signature hash version (0=legacy, 1=segwit).
 * @throws {ScriptError} Will be thrown on VERIFY failures, among other things.
 * @returns {Boolean} Whether the execution was successful.
 */

Script.prototype.execute = function execute(stack, flags, tx, index, version) {
  var ip = 0;
  var lastSep = 0;
  var opCount = 0;
  var alt = [];
  var state = [];
  var negate = 0;
  var op, val, v1, v2, v3;
  var n, n1, n2, n3;
  var res, key, sig, type, subscript, hash;
  var i, j, m, ikey, isig;
  var locktime;

  if (flags == null)
    flags = constants.flags.STANDARD_VERIFY_FLAGS;

  if (this.getSize() > constants.script.MAX_SIZE)
    throw new ScriptError('SCRIPT_SIZE');

  for (ip = 0; ip < this.code.length; ip++) {
    op = this.code[ip];

    if (op.value === -1)
      throw new ScriptError('BAD_OPCODE', op, ip);

    if (op.data) {
      if (op.data.length > constants.script.MAX_PUSH)
        throw new ScriptError('PUSH_SIZE', op, ip);
      // Note that minimaldata is not checked
      // on unexecuted branches of code.
      if (negate === 0) {
        if (!Script.isMinimal(op.data, op.value, flags))
          throw new ScriptError('MINIMALDATA', op, ip);
        stack.push(op.data);
      }
      continue;
    }

    op = op.value;

    if (op > opcodes.OP_16 && ++opCount > constants.script.MAX_OPS)
      throw new ScriptError('OP_COUNT', op, ip);

    // It's very important to make a distiction
    // here: these opcodes will fail _even if they
    // are in unexecuted branches of code_. Whereas
    // a totally unknown opcode is fine as long as it
    // is unexecuted.
    switch (op) {
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
        throw new ScriptError('DISABLED_OPCODE', op, ip);
    }

    if (op >= opcodes.OP_IF && op <= opcodes.OP_ENDIF) {
      switch (op) {
        case opcodes.OP_IF:
        case opcodes.OP_NOTIF: {
          if (negate === 0) {
            if (stack.length < 1)
              throw new ScriptError('UNBALANCED_CONDITIONAL', op, ip);
            val = Script.bool(stack.pop());
            if (op === opcodes.OP_NOTIF)
              val = !val;
            state.push(val);
            if (!val)
              negate++;
          } else {
            state.push(false);
            negate++;
          }
          break;
        }
        case opcodes.OP_ELSE: {
          if (state.length === 0)
            throw new ScriptError('UNBALANCED_CONDITIONAL', op, ip);
          state[state.length - 1] = !state[state.length - 1];
          if (!state[state.length - 1])
            negate++;
          else
            negate--;
          break;
        }
        case opcodes.OP_ENDIF: {
          if (state.length === 0)
            throw new ScriptError('UNBALANCED_CONDITIONAL', op, ip);
          if (!state.pop())
            negate--;
          break;
        }
        case opcodes.OP_VERIF:
        case opcodes.OP_VERNOTIF: {
          throw new ScriptError('BAD_OPCODE', op, ip);
        }
        default: {
          assert.fatal(false, 'Fatal script error.');
        }
      }
      continue;
    }

    if (negate !== 0)
      continue;

    switch (op) {
      case opcodes.OP_0: {
        stack.push(STACK_FALSE);
        break;
      }
      case opcodes.OP_1NEGATE: {
        stack.push(STACK_NEGATE);
        break;
      }
      case opcodes.OP_1:
      case opcodes.OP_2:
      case opcodes.OP_3:
      case opcodes.OP_4:
      case opcodes.OP_5:
      case opcodes.OP_6:
      case opcodes.OP_7:
      case opcodes.OP_8:
      case opcodes.OP_9:
      case opcodes.OP_10:
      case opcodes.OP_11:
      case opcodes.OP_12:
      case opcodes.OP_13:
      case opcodes.OP_14:
      case opcodes.OP_15:
      case opcodes.OP_16: {
        stack.push(new Buffer([op - 0x50]));
        break;
      }
      case opcodes.OP_NOP: {
        break;
      }
      case opcodes.OP_CHECKLOCKTIMEVERIFY: {
        // OP_CHECKLOCKTIMEVERIFY = OP_NOP2
        if (!(flags & constants.flags.VERIFY_CHECKLOCKTIMEVERIFY)) {
          if (flags & constants.flags.VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
            throw new ScriptError('DISCOURAGE_UPGRADABLE_NOPS', op, ip);
          break;
        }

        if (!tx)
          throw new ScriptError('UNKNOWN_ERROR', 'No TX passed in.');

        if (stack.length === 0)
          throw new ScriptError('INVALID_STACK_OPERATION', op, ip);

        locktime = Script.num(stack.top(-1), flags, 5);

        if (locktime.cmpn(0) < 0)
          throw new ScriptError('NEGATIVE_LOCKTIME', op, ip);

        locktime = locktime.uand(utils.U32).toNumber();

        if (!Script.checkLocktime(locktime, tx, index))
          throw new ScriptError('UNSATISFIED_LOCKTIME', op, ip);

        break;
      }
      case opcodes.OP_CHECKSEQUENCEVERIFY: {
        // OP_CHECKSEQUENCEVERIFY = OP_NOP3
        if (!(flags & constants.flags.VERIFY_CHECKSEQUENCEVERIFY)) {
          if (flags & constants.flags.VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
            throw new ScriptError('DISCOURAGE_UPGRADABLE_NOPS', op, ip);
          break;
        }

        if (!tx)
          throw new ScriptError('UNKNOWN_ERROR', 'No TX passed in.');

        if (stack.length === 0)
          throw new ScriptError('INVALID_STACK_OPERATION', op, ip);

        locktime = Script.num(stack.top(-1), flags, 5);

        if (locktime.cmpn(0) < 0)
          throw new ScriptError('NEGATIVE_LOCKTIME', op, ip);

        locktime = locktime.uand(utils.U32).toNumber();

        if ((locktime & constants.sequence.DISABLE_FLAG) !== 0)
          break;

        if (!Script.checkSequence(locktime, tx, index))
          throw new ScriptError('UNSATISFIED_LOCKTIME', op, ip);

        break;
      }
      case opcodes.OP_NOP1:
      case opcodes.OP_NOP4:
      case opcodes.OP_NOP5:
      case opcodes.OP_NOP6:
      case opcodes.OP_NOP7:
      case opcodes.OP_NOP8:
      case opcodes.OP_NOP9:
      case opcodes.OP_NOP10: {
        if (flags & constants.flags.VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
          throw new ScriptError('DISCOURAGE_UPGRADABLE_NOPS', op, ip);
        break;
      }
      case opcodes.OP_VERIFY: {
        if (stack.length === 0)
          throw new ScriptError('INVALID_STACK_OPERATION', op, ip);
        if (!Script.bool(stack.pop()))
          throw new ScriptError('VERIFY', op, ip);
        break;
      }
      case opcodes.OP_RETURN: {
        throw new ScriptError('OP_RETURN', op, ip);
      }
      case opcodes.OP_TOALTSTACK: {
        stack.toalt(alt);
        break;
      }
      case opcodes.OP_FROMALTSTACK: {
        stack.fromalt(alt);
        break;
      }
      case opcodes.OP_2DROP: {
        stack.drop2();
        break;
      }
      case opcodes.OP_2DUP: {
        stack.dup2();
        break;
      }
      case opcodes.OP_3DUP: {
        stack.dup3();
        break;
      }
      case opcodes.OP_2OVER: {
        stack.over2();
        break;
      }
      case opcodes.OP_2ROT: {
        stack.rot2();
        break;
      }
      case opcodes.OP_2SWAP: {
        stack.swap2();
        break;
      }
      case opcodes.OP_IFDUP: {
        stack.ifdup();
        break;
      }
      case opcodes.OP_DEPTH: {
        stack.depth();
        break;
      }
      case opcodes.OP_DROP: {
        stack.drop();
        break;
      }
      case opcodes.OP_DUP: {
        stack.dup();
        break;
      }
      case opcodes.OP_NIP: {
        stack.nip();
        break;
      }
      case opcodes.OP_OVER: {
        stack.over();
        break;
      }
      case opcodes.OP_PICK: {
        stack.pick(flags);
        break;
      }
      case opcodes.OP_ROLL: {
        stack.roll(flags);
        break;
      }
      case opcodes.OP_ROT: {
        stack.rot();
        break;
      }
      case opcodes.OP_SWAP: {
        stack.swap();
        break;
      }
      case opcodes.OP_TUCK: {
        stack.tuck();
        break;
      }
      case opcodes.OP_SIZE: {
        stack.size();
        break;
      }
      case opcodes.OP_EQUAL:
      case opcodes.OP_EQUALVERIFY: {
        if (stack.length < 2)
          throw new ScriptError('INVALID_STACK_OPERATION', op, ip);
        res = utils.equal(stack.pop(), stack.pop());
        if (op === opcodes.OP_EQUALVERIFY) {
          if (!res)
            throw new ScriptError('EQUALVERIFY', op, ip);
        } else {
          stack.push(res ? STACK_TRUE : STACK_FALSE);
        }
        break;
      }
      case opcodes.OP_1ADD:
      case opcodes.OP_1SUB:
      case opcodes.OP_2MUL:
      case opcodes.OP_2DIV:
      case opcodes.OP_NEGATE:
      case opcodes.OP_ABS:
      case opcodes.OP_NOT:
      case opcodes.OP_0NOTEQUAL: {
        if (stack.length < 1)
          throw new ScriptError('INVALID_STACK_OPERATION', op, ip);
        n = Script.num(stack.pop(), flags);
        switch (op) {
          case opcodes.OP_1ADD:
            n.iaddn(1);
            break;
          case opcodes.OP_1SUB:
            n.isubn(1);
            break;
          case opcodes.OP_2MUL:
            n.iushln(1);
            break;
          case opcodes.OP_2DIV:
            n.iushrn(1);
            break;
          case opcodes.OP_NEGATE:
            n.ineg();
            break;
          case opcodes.OP_ABS:
            if (n.cmpn(0) < 0)
              n.ineg();
            break;
          case opcodes.OP_NOT:
            n = n.cmpn(0) === 0;
            break;
          case opcodes.OP_0NOTEQUAL:
            n = n.cmpn(0) !== 0;
            break;
          default:
            assert.fatal(false, 'Fatal script error.');
        }
        if (typeof n === 'boolean')
          n = new bn(n ? 1 : 0);
        stack.push(Script.array(n));
        break;
      }
      case opcodes.OP_ADD:
      case opcodes.OP_SUB:
      case opcodes.OP_MUL:
      case opcodes.OP_DIV:
      case opcodes.OP_MOD:
      case opcodes.OP_LSHIFT:
      case opcodes.OP_RSHIFT:
      case opcodes.OP_BOOLAND:
      case opcodes.OP_BOOLOR:
      case opcodes.OP_NUMEQUAL:
      case opcodes.OP_NUMEQUALVERIFY:
      case opcodes.OP_NUMNOTEQUAL:
      case opcodes.OP_LESSTHAN:
      case opcodes.OP_GREATERTHAN:
      case opcodes.OP_LESSTHANOREQUAL:
      case opcodes.OP_GREATERTHANOREQUAL:
      case opcodes.OP_MIN:
      case opcodes.OP_MAX: {
        switch (op) {
          case opcodes.OP_ADD:
          case opcodes.OP_SUB:
          case opcodes.OP_MUL:
          case opcodes.OP_DIV:
          case opcodes.OP_MOD:
          case opcodes.OP_LSHIFT:
          case opcodes.OP_RSHIFT:
          case opcodes.OP_BOOLAND:
          case opcodes.OP_BOOLOR:
          case opcodes.OP_NUMEQUAL:
          case opcodes.OP_NUMEQUALVERIFY:
          case opcodes.OP_NUMNOTEQUAL:
          case opcodes.OP_LESSTHAN:
          case opcodes.OP_GREATERTHAN:
          case opcodes.OP_LESSTHANOREQUAL:
          case opcodes.OP_GREATERTHANOREQUAL:
          case opcodes.OP_MIN:
          case opcodes.OP_MAX:
            if (stack.length < 2)
              throw new ScriptError('INVALID_STACK_OPERATION', op, ip);
            n2 = Script.num(stack.pop(), flags);
            n1 = Script.num(stack.pop(), flags);
            n = new bn(0);
            switch (op) {
              case opcodes.OP_ADD:
                n = n1.add(n2);
                break;
              case opcodes.OP_SUB:
                n = n1.sub(n2);
                break;
              case opcodes.OP_MUL:
                n = n1.mul(n2);
                break;
              case opcodes.OP_DIV:
                n = n1.div(n2);
                break;
              case opcodes.OP_MOD:
                n = n1.mod(n2);
                break;
              case opcodes.OP_LSHIFT:
                if (n2.cmpn(0) < 0 || n2.cmpn(2048) > 0)
                  throw new ScriptError('UNKNOWN_ERROR', 'Bad shift.');
                n = n1.ushln(n2.toNumber());
                break;
              case opcodes.OP_RSHIFT:
                if (n2.cmpn(0) < 0 || n2.cmpn(2048) > 0)
                  throw new ScriptError('UNKNOWN_ERROR', 'Bad shift.');
                n = n1.ushrn(n2.toNumber());
                break;
              case opcodes.OP_BOOLAND:
                n = n1.cmpn(0) !== 0 && n2.cmpn(0) !== 0;
                break;
              case opcodes.OP_BOOLOR:
                n = n1.cmpn(0) !== 0 || n2.cmpn(0) !== 0;
                break;
              case opcodes.OP_NUMEQUAL:
                n = n1.cmp(n2) === 0;
                break;
              case opcodes.OP_NUMEQUALVERIFY:
                n = n1.cmp(n2) === 0;
                break;
              case opcodes.OP_NUMNOTEQUAL:
                n = n1.cmp(n2) !== 0;
                break;
              case opcodes.OP_LESSTHAN:
                n = n1.cmp(n2) < 0;
                break;
              case opcodes.OP_GREATERTHAN:
                n = n1.cmp(n2) > 0;
                break;
              case opcodes.OP_LESSTHANOREQUAL:
                n = n1.cmp(n2) <= 0;
                break;
              case opcodes.OP_GREATERTHANOREQUAL:
                n = n1.cmp(n2) >= 0;
                break;
              case opcodes.OP_MIN:
                n = n1.cmp(n2) < 0 ? n1 : n2;
                break;
              case opcodes.OP_MAX:
                n = n1.cmp(n2) > 0 ? n1 : n2;
                break;
              default:
                assert.fatal(false, 'Fatal script error.');
            }
            if (typeof n === 'boolean')
              n = new bn(n ? 1 : 0);
            if (op === opcodes.OP_NUMEQUALVERIFY) {
              if (!Script.bool(n))
                throw new ScriptError('NUMEQUALVERIFY', op, ip);
            } else {
              stack.push(Script.array(n));
            }
            break;
        }

        break;
      }
      case opcodes.OP_WITHIN: {
        if (stack.length < 3)
          throw new ScriptError('INVALID_STACK_OPERATION', op, ip);
        n3 = Script.num(stack.pop(), flags);
        n2 = Script.num(stack.pop(), flags);
        n1 = Script.num(stack.pop(), flags);
        val = n2.cmp(n1) <= 0 && n1.cmp(n3) < 0;
        stack.push(val ? STACK_TRUE : STACK_FALSE);
        break;
      }
      case opcodes.OP_RIPEMD160: {
        if (stack.length === 0)
          throw new ScriptError('INVALID_STACK_OPERATION', op, ip);
        stack.push(utils.ripemd160(stack.pop()));
        break;
      }
      case opcodes.OP_SHA1: {
        if (stack.length === 0)
          throw new ScriptError('INVALID_STACK_OPERATION', op, ip);
        stack.push(utils.sha1(stack.pop()));
        break;
      }
      case opcodes.OP_SHA256: {
        if (stack.length === 0)
          throw new ScriptError('INVALID_STACK_OPERATION', op, ip);
        stack.push(utils.sha256(stack.pop()));
        break;
      }
      case opcodes.OP_HASH256: {
        if (stack.length === 0)
          throw new ScriptError('INVALID_STACK_OPERATION', op, ip);
        stack.push(utils.dsha256(stack.pop()));
        break;
      }
      case opcodes.OP_HASH160: {
        if (stack.length === 0)
          throw new ScriptError('INVALID_STACK_OPERATION', op, ip);
        stack.push(utils.ripesha(stack.pop()));
        break;
      }
      case opcodes.OP_CODESEPARATOR: {
        lastSep = ip;
        break;
      }
      case opcodes.OP_CHECKSIGVERIFY:
      case opcodes.OP_CHECKSIG: {
        if (!tx)
          throw new ScriptError('UNKNOWN_ERROR', 'No TX passed in.');

        if (stack.length < 2)
          throw new ScriptError('INVALID_STACK_OPERATION', op, ip);

        key = stack.pop();
        sig = stack.pop();

        subscript = this.getSubscript(lastSep);
        if (version === 0)
          subscript.removeData(sig);

        Script.validateSignature(sig, flags);
        Script.validateKey(key, flags);

        type = sig[sig.length - 1];

        hash = tx.signatureHash(index, subscript, type, version);

        res = Script.checksig(hash, sig, key, flags);
        if (op === opcodes.OP_CHECKSIGVERIFY) {
          if (!res)
            throw new ScriptError('CHECKSIGVERIFY', op, ip);
        } else {
          stack.push(res ? STACK_TRUE : STACK_FALSE);
        }

        break;
      }
      case opcodes.OP_CHECKMULTISIGVERIFY:
      case opcodes.OP_CHECKMULTISIG: {
        if (!tx)
          throw new ScriptError('UNKNOWN_ERROR', 'No TX passed in.');

        i = 1;
        if (stack.length < i)
          throw new ScriptError('INVALID_STACK_OPERATION', op, ip);

        n = Script.num(stack.top(-i), flags).toNumber();

        if (!(n >= 0 && n <= constants.script.MAX_MULTISIG_PUBKEYS))
          throw new ScriptError('PUBKEY_COUNT', op, ip);

        opCount += n;

        if (opCount > constants.script.MAX_OPS)
          throw new ScriptError('OP_COUNT', op, ip);

        i++;
        ikey = i;
        i += n;

        if (stack.length < i)
          throw new ScriptError('INVALID_STACK_OPERATION', op, ip);

        m = Script.num(stack.top(-i), flags).toNumber();

        if (!(m >= 0 && m <= n))
          throw new ScriptError('SIG_COUNT', op, ip);

        i++;
        isig = i;
        i += m;

        if (stack.length < i)
          throw new ScriptError('INVALID_STACK_OPERATION', op, ip);

        subscript = this.getSubscript(lastSep);

        for (j = 0; j < m; j++) {
          sig = stack.top(-isig - j);
          if (version === 0)
            subscript.removeData(sig);
        }

        res = true;
        while (res && m > 0) {
          sig = stack.top(-isig);
          key = stack.top(-ikey);

          Script.validateSignature(sig, flags);
          Script.validateKey(key, flags);

          type = sig[sig.length - 1];
          hash = tx.signatureHash(index, subscript, type, version);

          if (Script.checksig(hash, sig, key, flags)) {
            isig++;
            m--;
          }

          ikey++;
          n--;

          if (m > n)
            res = false;
        }

        while (i-- > 1)
          stack.pop();

        if (stack.length < 1)
          throw new ScriptError('INVALID_STACK_OPERATION', op, ip);

        if (flags & constants.flags.VERIFY_NULLDUMMY) {
          if (!Script.isDummy(stack.top(-1)))
            throw new ScriptError('SIG_NULLDUMMY', op, ip);
        }

        stack.pop();

        if (op === opcodes.OP_CHECKMULTISIGVERIFY) {
          if (!res)
            throw new ScriptError('CHECKMULTISIGVERIFY', op, ip);
        } else {
          stack.push(res ? STACK_TRUE : STACK_FALSE);
        }

        break;
      }
      case opcodes.OP_CAT: {
        if (stack.length < 2)
          throw new ScriptError('INVALID_STACK_OPERATION', op, ip);
        v2 = stack.pop();
        v1 = stack.pop();
        stack.push(Buffer.concat([v1, v2]));
        if (stack.top(-1).length > constants.script.MAX_PUSH)
          throw new ScriptError('PUSH_SIZE', op, ip);
        break;
      }
      case opcodes.OP_SUBSTR: {
        if (stack.length < 3)
          throw new ScriptError('INVALID_STACK_OPERATION', op, ip);
        v3 = Script.num(stack.pop(), flags).toNumber(); // end
        v2 = Script.num(stack.pop(), flags).toNumber(); // begin
        v1 = stack.pop(); // string
        if (v2 < 0 || v3 < v2)
          throw new ScriptError('UNKNOWN_ERROR', 'String out of range.');
        if (v2 > v1.length)
          v2 = v1.length;
        if (v3 > v1.length)
          v3 = v1.length;
        stack.push(v1.slice(v2, v3));
        break;
      }
      case opcodes.OP_LEFT:
      case opcodes.OP_RIGHT: {
        if (stack.length < 2)
          throw new ScriptError('INVALID_STACK_OPERATION', op, ip);
        v2 = Script.num(stack.pop(), flags).toNumber(); // size
        v1 = stack.pop(); // string
        if (v2 < 0)
          throw new ScriptError('UNKNOWN_ERROR', 'String size out of range.');
        if (v2 > v1.length)
          v2 = v1.length;
        if (op === opcodes.OP_LEFT)
          v1 = v1.slice(0, v2);
        else
          v1 = v1.slice(v1.length - v2);
        stack.push(v1);
        break;
      }
      case opcodes.OP_INVERT: {
        if (stack.length < 1)
          throw new ScriptError('INVALID_STACK_OPERATION', op, ip);
        val = utils.copy(stack.pop());
        for (i = 0; i < val.length; i++)
          val[i] = ~val[i] & 0xff;
        stack.push(val);
        break;
      }
      case opcodes.OP_AND:
      case opcodes.OP_OR:
      case opcodes.OP_XOR: {
        if (stack.length < 2)
          throw new ScriptError('INVALID_STACK_OPERATION', op, ip);
        v2 = stack.pop();
        v1 = utils.copy(stack.pop());
        if (v1.length < v2.length) {
          v3 = new Buffer(v2.length - v1.length);
          v3.fill(0);
          v1 = Buffer.concat([v1, v3]);
        }
        if (v2.length < v1.length) {
          v3 = new Buffer(v1.length - v2.length);
          v3.fill(0);
          v2 = Buffer.concat([v2, v3]);
        }
        if (op === opcodes.OP_AND) {
          for (i = 0; i < v1.length; i++)
            v1[i] &= v2[i];
        } else if (op === opcodes.OP_OR) {
          for (i = 0; i < v1.length; i++)
            v1[i] |= v2[i];
        } else if (op === opcodes.OP_XOR) {
          for (i = 0; i < v1.length; i++)
            v1[i] ^= v2[i];
        }
        stack.push(v1);
        break;
      }
      default: {
        throw new ScriptError('BAD_OPCODE', op, ip);
      }
    }
  }

  if (stack.getSize(alt) > constants.script.MAX_STACK)
    throw new ScriptError('STACK_SIZE', op, ip);

  if (state.length !== 0)
    throw new ScriptError('UNBALANCED_CONDITIONAL', op, ip);

  return true;
};

/**
 * Verify the nLockTime of a transaction.
 * @param {Number} locktime - Locktime to verify against (max=u32).
 * @param {TX} tx - Transaction to verify.
 * @param {Number} index - Index of input being verified (for IsFinal).
 * @returns {Boolean}
 */

Script.checkLocktime = function checkLocktime(locktime, tx, i) {
  var threshold = constants.LOCKTIME_THRESHOLD;

  if (!(
    (tx.locktime < threshold && locktime < threshold)
    || (tx.locktime >= threshold && locktime >= threshold)
  )) {
    return false;
  }

  if (locktime > tx.locktime)
    return false;

  if (tx.inputs[i].sequence === 0xffffffff)
    return false;

  return true;
};

/**
 * Verify the nSequence locktime of a transaction.
 * @param {Number} sequence - Locktime to verify against (max=u32).
 * @param {TX} tx - Transaction to verify.
 * @param {Number} index - Index of input being verified.
 * @returns {Boolean}
 */

Script.checkSequence = function checkSequence(sequence, tx, i) {
  var txSequence = tx.inputs[i].sequence;
  var locktimeMask, txSequenceMasked, sequenceMasked;

  if (tx.version < 2)
    return false;

  if (txSequence & constants.sequence.DISABLE_FLAG)
    return false;

  locktimeMask = constants.sequence.TYPE_FLAG
    | constants.sequence.MASK;
  txSequenceMasked = txSequence & locktimeMask;
  sequenceMasked = sequence & locktimeMask;

  if (!(
    (txSequenceMasked < constants.sequence.TYPE_FLAG
    && sequenceMasked < constants.sequence.TYPE_FLAG)
    || (txSequenceMasked >= constants.sequence.TYPE_FLAG
    && sequenceMasked >= constants.sequence.TYPE_FLAG)
  )) {
    return false;
  }

  if (sequenceMasked > txSequenceMasked)
    return false;

  return true;
};

/**
 * Cast a big number or Buffer to a bool.
 * @see CastToBool
 * @param {BN|Buffer} value
 * @returns {Boolean}
 */

Script.bool = function bool(value) {
  var i;

  if (bn.isBN(value))
    return value.cmpn(0) !== 0;

  assert(Buffer.isBuffer(value));

  for (i = 0; i < value.length; i++) {
    if (value[i] !== 0) {
      // Cannot be negative zero
      if (i === value.length - 1 && value[i] === 0x80)
        return false;
      return true;
    }
  }

  return false;
};

/**
 * Create a CScriptNum.
 * @param {Buffer} value
 * @param {Number?} flags - Script standard flags.
 * @param {Number?} size - Max size in bytes.
 * @returns {BN}
 * @throws {ScriptError}
 */

Script.num = function num(value, flags, size) {
  var result;

  assert(Buffer.isBuffer(value));

  if (flags == null)
    flags = constants.flags.STANDARD_VERIFY_FLAGS;

  if (size == null)
    size = 4;

  if (value.length > size)
    throw new ScriptError('UNKNOWN_ERROR', 'Script number overflow.');

  if ((flags & constants.flags.VERIFY_MINIMALDATA) && value.length > 0) {
    // If the low bits on the last byte are unset,
    // fail if the value's second to last byte does
    // not have the high bit set. A number can't
    // justify having the last byte's low bits unset
    // unless they ran out of space for the sign bit
    // in the second to last bit. We also fail on [0]
    // to avoid negative zero (also avoids positive
    // zero).
    if (!(value[value.length - 1] & 0x7f)) {
      if (value.length === 1 || !(value[value.length - 2] & 0x80)) {
        throw new ScriptError(
          'UNKNOWN_ERROR',
          'Non-minimally encoded Script number.');
      }
    }
  }

  if (value.length === 0)
    return new bn(0);

  result = new bn(value, 'le');

  // If the input vector's most significant byte is
  // 0x80, remove it from the result's msb and return
  // a negative.
  // Equivalent to:
  // -(result & ~(0x80 << (8 * (value.length - 1))))
  if (value[value.length - 1] & 0x80)
    result.setn((value.length * 8) - 1, 0).ineg();

  return result;
};

/**
 * Create a script array. Will convert Numbers and big
 * numbers to a little-endian buffer while taking into
 * account negative zero, minimaldata, etc.
 * @example
 * assert.deepEqual(Script.array(0), new Buffer([]));
 * assert.deepEqual(Script.array(0xffee), new Buffer([0xee, 0xff, 0x00]));
 * assert.deepEqual(Script.array(new bn(0xffee)), new Buffer([0xee, 0xff, 0x00]));
 * assert.deepEqual(Script.array(new bn(0x1e).ineg()), new Buffer([0x9e]));
 * @param {Buffer|Number|BN} value
 * @returns {Buffer}
 */

Script.array = function(value) {
  var neg, result;

  if (Buffer.isBuffer(value))
    return value;

  if (utils.isNumber(value))
    value = new bn(value);

  assert(bn.isBN(value));

  if (value.cmpn(0) === 0)
    return STACK_FALSE;

  // If the most significant byte is >= 0x80
  // and the value is positive, push a new
  // zero-byte to make the significant
  // byte < 0x80 again.

  // If the most significant byte is >= 0x80
  // and the value is negative, push a new
  // 0x80 byte that will be popped off when
  // converting to an integral.

  // If the most significant byte is < 0x80
  // and the value is negative, add 0x80 to
  // it, since it will be subtracted and
  // interpreted as a negative when
  // converting to an integral.

  neg = value.cmpn(0) < 0;
  result = value.toArray('le');

  if (result[result.length - 1] & 0x80)
    result.push(neg ? 0x80 : 0);
  else if (neg)
    result[result.length - 1] |= 0x80;

  return new Buffer(result);
};

/**
 * Remove all matched data elements from
 * a script's code (used to remove signatures
 * before verification). Note that this
 * compares and removes data on the _byte level_.
 * It also reserializes the data to a single
 * script with minimaldata encoding beforehand.
 * A signature will _not_ be removed if it is
 * not minimaldata.
 * @see https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2014-November/006878.html
 * @see https://test.webbtc.com/tx/19aa42fee0fa57c45d3b16488198b27caaacc4ff5794510d0c17f173f05587ff
 * @param {Buffer} data - Data element to match against.
 * @returns {Number} Total.
 */

Script.prototype.removeData = function removeData(data) {
  var index = [];
  var i, op;

  // We need to go forward first. We can't go
  // backwards (this is consensus code and we
  // need to be aware of bad pushes).
  for (i = 0; i < this.code.length; i++) {
    op = this.code[i];

    if (op.value === -1)
      break;

    if (!op.data)
      continue;

    if (!Script.isMinimal(op.data, op.value))
      continue;

    if (utils.equal(op.data, data))
      index.push(i);
  }

  if (index.length === 0)
    return 0;

  // Go backwards and splice out the data.
  for (i = index.length - 1; i >= 0; i--)
    this.code.splice(index[i], 1);

  this.raw = Script.encode(this.code);

  return index.length;
};

/**
 * Find a data element in a script.
 * @param {Buffer} data - Data element to match against.
 * @returns {Number} Index (`-1` if not present).
 */

Script.prototype.indexOf = function indexOf(data) {
  var i, op;

  for (i = 0; i < this.code.length; i++) {
    op = this.code[i];

    if (op.value === -1)
      break;

    if (!op.data)
      continue;

    if (utils.equal(op.data, data))
      return i;
  }

  return -1;
};

/**
 * Check to see if a pushdata Buffer abides by minimaldata.
 * @param {Buffer} data
 * @param {Number} opcode
 * @param {Number?} flags
 * @returns {Boolean}
 */

Script.isMinimal = function isMinimal(data, opcode, flags) {
  if (flags == null)
    flags = constants.flags.STANDARD_VERIFY_FLAGS;

  if (!(flags & constants.flags.VERIFY_MINIMALDATA))
    return true;

  if (!data)
    return true;

  if (data.length === 0)
    return opcode === opcodes.OP_0;

  if (data.length === 1 && data[0] >= 1 && data[0] <= 16)
    return false;

  if (data.length === 1 && data[0] === 0x81)
    return false;

  if (data.length <= 75)
    return opcode === data.length;

  if (data.length <= 255)
    return opcode === opcodes.OP_PUSHDATA1;

  if (data.length <= 65535)
    return opcode === opcodes.OP_PUSHDATA2;

  return true;
};

/**
 * Test a buffer to see if it is valid script code (no non-existent opcodes).
 * @param {Buffer} raw
 * @returns {Boolean}
 */

Script.isCode = function isCode(raw) {
  var i, op, code;

  if (!raw)
    return false;

  if (!Buffer.isBuffer(raw))
    return false;

  code = Script.decode(raw);

  for (i = 0; i < code.length; i++) {
    op = code[i];

    if (op.data)
      continue;

    if (op.value === -1)
      return false;

    if (constants.opcodesByVal[op.value] == null)
      return false;
  }

  return true;
};

/**
 * Create a pay-to-pubkey script.
 * @param {Buffer} key
 * @returns {Script}
 */

Script.createPubkey = function createPubkey(key) {
  assert(key.length >= 33);
  return Script.fromArray([key, opcodes.OP_CHECKSIG]);
};

/**
 * Create a pay-to-pubkeyhash script.
 * @param {Buffer} hash
 * @returns {Script}
 */

Script.createPubkeyhash = function createPubkeyhash(hash) {
  assert(hash.length === 20);
  return Script.fromArray([
    opcodes.OP_DUP,
    opcodes.OP_HASH160,
    hash,
    opcodes.OP_EQUALVERIFY,
    opcodes.OP_CHECKSIG
  ]);
};

/**
 * Create a pay-to-multisig script.
 * @param {Buffer[]} keys
 * @param {Number} m
 * @param {Number} n
 * @returns {Script}
 */

Script.createMultisig = function createMultisig(keys, m, n) {
  var code = [];
  var i;

  assert(keys.length === n, '`n` keys are required for multisig.');
  assert(m >= 1 && m <= n);
  assert(n >= 1 && n <= 15);

  keys = utils.sortKeys(keys);

  code.push(m + 0x50);

  for (i = 0; i < keys.length; i++)
    code.push(keys[i]);

  code.push(n + 0x50);
  code.push(opcodes.OP_CHECKMULTISIG);

  return Script.fromArray(code);
};

/**
 * Create a pay-to-scripthash script.
 * @param {Buffer} hash
 * @returns {Script}
 */

Script.createScripthash = function createScripthash(hash) {
  assert(hash.length === 20);
  return Script.fromArray([
    opcodes.OP_HASH160,
    hash,
    opcodes.OP_EQUAL
  ]);
};

/**
 * Create a nulldata/opreturn script.
 * @param {Buffer} flags
 * @returns {Script}
 */

Script.createNulldata = function createNulldata(flags) {
  assert(Buffer.isBuffer(flags));
  assert(flags.length <= constants.script.MAX_OP_RETURN, 'Nulldata too large.');
  return Script.fromArray([
    opcodes.OP_RETURN,
    flags
  ]);
};

/**
 * Create a witness program.
 * @param {Number} version
 * @param {Buffer} data
 * @returns {Script}
 */

Script.createWitnessProgram = function createWitnessProgram(version, data) {
  assert(typeof version === 'number' && version >= 0 && version <= 16);
  assert(data.length >= 2 && data.length <= 32);
  return Script.fromArray([version === 0 ? 0 : version + 0x50, data]);
};

/**
 * Create a witness block commitment.
 * @param {Buffer} hash
 * @param {String|Buffer} flags
 * @returns {Script}
 */

Script.createCommitment = function createCommitment(hash, flags) {
  var p;

  if (!flags)
    flags = 'mined by bcoin';

  if (typeof flags === 'string')
    flags = new Buffer(flags, 'utf8');

  p = new BufferWriter();
  p.writeU32BE(0xaa21a9ed);
  p.writeHash(hash);

  return Script.fromArray([
    opcodes.OP_RETURN,
    p.render(),
    flags
  ]);
};

/**
 * Grab and deserialize the redeem script.
 * @returns {Script|null} Redeem script.
 */

Script.prototype.getRedeem = function getRedeem() {
  var redeem;

  if (!this.redeem) {
    if (!this.isPushOnly())
      return;

    redeem = this.code[this.code.length - 1];

    if (!redeem || !redeem.data)
      return;

    this.redeem = new Script(redeem.data);
  }

  return this.redeem;
};

/**
 * Get the standard script type.
 * @returns {String} Script script (can be
 * any of 'witnesspubkeyhash', 'witnessscripthash',
 * 'pubkey', 'multisig', 'scripthash', 'nulldata',
 * or 'unknown').
 */

Script.prototype.getType = function getType() {
  if (this.isWitnessProgram()) {
    if (this.isWitnessPubkeyhash())
      return 'witnesspubkeyhash';
    if (this.isWitnessScripthash())
      return 'witnessscripthash';
    return 'unknown';
  }

  return (this.isPubkey() && 'pubkey')
    || (this.isPubkeyhash() && 'pubkeyhash')
    || (this.isMultisig() && 'multisig')
    || (this.isScripthash() && 'scripthash')
    || (this.isNulldata() && 'nulldata')
    || 'unknown';
};

/**
 * Test whether a script is of an unknown/non-standard type.
 * @returns {Boolean}
 */

Script.prototype.isUnknown = function isUnknown() {
  return this.getType() === 'unknown';
};

/**
 * Test whether the script is standard by policy standards.
 * @returns {Boolean}
 */

Script.prototype.isStandard = function isStandard() {
  var type = this.getType();
  var m, n;

  if (type === 'multisig') {
    m = Script.getSmall(this.raw[0]);
    n = Script.getSmall(this.raw[this.raw.length - 2]);

    if (n < 1 || n > 3)
      return false;

    if (m < 1 || m > n)
      return false;
  }

  return type !== 'unknown';
};

/**
 * Calculate size of script excluding the varint size bytes.
 * @returns {Number}
 */

Script.prototype.getSize = function getSize() {
  return this.raw.length;
};

/**
 * "Guess" the address of the input script.
 * This method is not 100% reliable.
 * @returns {Base58Address|null}
 */

Script.prototype.getInputAddress = function getInputAddress() {
  return bcoin.address.fromInputScript(this);
};

/**
 * Get the address of the script if present. Note that
 * pubkey and multisig scripts will be treated as though
 * they are pubkeyhash and scripthashes respectively.
 * @returns {Base58Address|null}
 */

Script.prototype.getAddress = function getAddress() {
  return bcoin.address.fromScript(this);
};

/**
 * Test whether the output script is pay-to-pubkey.
 * @param {Boolean} [sloppy=false] - Allow non-minimal scripts.
 * @returns {Boolean}
 */

Script.prototype.isPubkey = function isPubkey(sloppy) {
  if (sloppy) {
    return this.code.length === 2
      && Script.isKey(this.code[0].data)
      && this.code[1].value === opcodes.OP_CHECKSIG;
  }

  return this.raw[0] >= 33 && this.raw[0] <= 65
    && this.raw[0] + 2 === this.raw.length
    && this.raw[this.raw.length - 1] === opcodes.OP_CHECKSIG;
};

/**
 * Test whether the output script is pay-to-pubkeyhash.
 * @param {Boolean} [sloppy=false] - Allow non-minimal scripts.
 * @returns {Boolean}
 */

Script.prototype.isPubkeyhash = function isPubkeyhash(sloppy) {
  if (sloppy) {
    return this.code.length === 5
      && this.code[0].value === opcodes.OP_DUP
      && this.code[1].value === opcodes.OP_HASH160
      && Script.isHash(this.code[2].data)
      && this.code[3].value === opcodes.OP_EQUALVERIFY
      && this.code[4].value === opcodes.OP_CHECKSIG;
  }

  return this.raw.length === 25
    && this.raw[0] === opcodes.OP_DUP
    && this.raw[1] === opcodes.OP_HASH160
    && this.raw[2] === 0x14
    && this.raw[23] === opcodes.OP_EQUALVERIFY
    && this.raw[24] === opcodes.OP_CHECKSIG;
};

/**
 * Test whether the output script is pay-to-multisig.
 * @returns {Boolean}
 */

Script.prototype.isMultisig = function isMultisig() {
  var m, n, i;

  if (this.raw.length < 41)
    return false;

  if (this.raw[this.raw.length - 1] !== opcodes.OP_CHECKMULTISIG)
    return false;

  n = Script.getSmall(this.raw[this.raw.length - 2]);

  if (n < 1)
    return false;

  m = Script.getSmall(this.raw[0]);

  if (!(m >= 1 && m <= n))
    return false;

  if (n + 3 !== this.code.length)
    return false;

  for (i = 1; i < n + 1; i++) {
    if (!Script.isKey(this.code[i].data))
      return false;
  }

  return true;
};

/**
 * Test whether the output script is pay-to-scripthash. Note that
 * bitcoin itself requires scripthashes to be in strict minimaldata
 * encoding. Using `OP_HASH160 OP_PUSHDATA1 [hash] OP_EQUAL` will
 * _not_ be recognized as a scripthash.
 * @returns {Boolean}
 */

Script.prototype.isScripthash = function isScripthash() {
  return this.raw.length === 23
    && this.raw[0] === opcodes.OP_HASH160
    && this.raw[1] === 0x14
    && this.raw[22] === opcodes.OP_EQUAL;
};

/**
 * Test whether the output script is nulldata/opreturn.
 * @param {Boolean} [sloppy=false] - Allow non-minimal scripts.
 * @returns {Boolean}
 */

Script.prototype.isNulldata = function isNulldata(sloppy) {
  var i, op;

  if (this.raw.length > constants.script.MAX_OP_RETURN_BYTES)
    return false;

  if (this.raw.length === 0)
    return false;

  if (this.raw[0] !== opcodes.OP_RETURN)
    return false;

  if (sloppy) {
    for (i = 1; i < this.code.length; i++) {
      op = this.code[i];
      if (op.data)
        continue;
      if (op.value === -1)
        return false;
      if (op.value > opcodes.OP_16)
        return false;
    }
    return true;
  }

  if (this.raw[1] >= 0x01 && this.raw[1] <= 0x4b) {
    if (this.raw[1] + 2 !== this.raw.length)
      return false;
    return true;
  }

  if (this.raw[1] === opcodes.OP_PUSHDATA1) {
    if (this.raw[2] + 3 !== this.raw.length)
      return false;
    return true;
  }

  return false;
};

/**
 * Test whether the output script is a segregated witness
 * commitment. Note that commitments are a superset of nulldata
 * as they can have multiple pushdata ops. When validating for
 * standardness, commitments should not be allowed in anything
 * but coinbases.
 * @returns {Boolean}
 */

Script.prototype.isCommitment = function isCommitment() {
  if (this.raw.length < 38)
    return false;
  if (this.raw[0] !== opcodes.OP_RETURN)
    return false;
  if (this.raw[1] !== 0x24)
    return false;
  if (this.raw.readUInt32BE(2, true) !== 0xaa21a9ed)
    return false;
  return true;
};

/**
 * Get the commitment hash if present.
 * @returns {Buffer|null}
 */

Script.prototype.getCommitmentHash = function getCommitmentHash() {
  if (!this.isCommitment())
    return;

  return this.raw.slice(6, 38);
};

/**
 * Test whether the output script is a witness program.
 * Note that this will return true even for malformed
 * witness v0 programs.
 * @return {Boolean}
 */

Script.prototype.isWitnessProgram = function isWitnessProgram() {
  if (!(this.raw.length >= 4 && this.raw.length <= 42))
    return false;

  if (this.raw[0] !== opcodes.OP_0
      && !(this.raw[0] >= opcodes.OP_1 && this.raw[0] <= opcodes.OP_16)) {
    return false;
  }

  if (this.raw[1] + 2 !== this.raw.length)
    return false;

  return true;
};

/**
 * Get the witness program if present.
 * @returns {Program|null}
 */

Script.prototype.getWitnessProgram = function getWitnessProgram() {
  var version, data, type;

  if (!this.isWitnessProgram())
    return;

  version = Script.getSmall(this.raw[0]);
  data = this.raw.slice(2);

  if (version > 0) {
    // No interpretation of script (anyone can spend)
    type = 'unknown';
  } else if (version === 0 && data.length === 20) {
    type = 'witnesspubkeyhash';
  } else if (version === 0 && data.length === 32) {
    type = 'witnessscripthash';
  } else {
    // Fail on bad version=0
    type = null;
  }

  return {
    version: version,
    type: type,
    data: data
  };
};

/**
 * Test whether the output script is a pay-to-witness-pubkeyhash script.
 * @returns {Boolean}
 */

Script.prototype.isWitnessPubkeyhash = function isWitnessPubkeyhash() {
  return this.raw.length === 22
    && this.raw[0] === opcodes.OP_0
    && this.raw[1] === 0x14;
};

/**
 * Test whether the output script is a pay-to-witness-scripthash script.
 * @returns {Boolean}
 */

Script.prototype.isWitnessScripthash = function isWitnessScripthash() {
  return this.raw.length === 34
    && this.raw[0] === opcodes.OP_0
    && this.raw[1] === 0x20;
};

/**
 * Test whether the output script is unspendable.
 * @returns {Boolean}
 */

Script.prototype.isUnspendable = function isUnspendable() {
  return this.raw.length > 0 && this.raw[0] === opcodes.OP_RETURN;
};

/**
 * "Guess" the type of the input script.
 * This method is not 100% reliable.
 * @returns {String}
 */

Script.prototype.getInputType = function getInputType() {
  return (this.isPubkeyInput() && 'pubkey')
    || (this.isPubkeyhashInput() && 'pubkeyhash')
    || (this.isMultisigInput() && 'multisig')
    || (this.isScripthashInput() && 'scripthash')
    || 'unknown';
};

/**
 * "Guess" whether the input script is an unknown/non-standard type.
 * This method is not 100% reliable.
 * @returns {Boolean}
 */

Script.prototype.isUnknownInput = function isUnknownInput() {
  return this.getInputType() === 'unknown';
};

/**
 * Automatically build an output script from any number of options.
 * @example
 * Script.createOutputScript({ address: '1HT7xU2Ngenf7D4yocz2SAcnNLW7rK8d4E' });
 * @param {Object} options
 * @param {(Address|Base58Address)?} options.address - Address to send to.
 * @param {Buffer?} options.flags - Nulldata flags.
 * @param {Buffer?} options.key - Key for pay-to-pubkey.
 * @param {Buffer?} options.keyHash - Key has for pay-to-pubkeyhash.
 * @param {Buffer[]?} options.keys - Keys for pay-to-multisig.
 * @param {Buffer} options.scriptHash - Whether to create a scripthash
 * @returns {Script}
 */

Script.createOutputScript = function createOutputScript(options) {
  var m, n, flags, address;

  if (!options)
    options = {};

  if (options.address) {
    address = options.address;
    if (typeof address === 'string')
      address = bcoin.address.fromBase58(address);
    return address.toScript();
  }

  if (options.flags) {
    flags = options.flags;
    if (typeof flags === 'string')
      flags = new Buffer(flags, 'utf8');
    return Script.createNulldata(flags);
  }

  if (options.key)
    return Script.createPubkey(options.key);

  if (options.keyHash) {
    if (options.version != null)
      return Script.createWitnessProgram(options.version, options.keyHash);
    return Script.createPubkeyhash(options.keyHash);
  }

  if (options.keys) {
    m = options.m;
    n = options.n || options.keys.length;
    return Script.createMultisig(options.keys, m, n);
  }

  if (options.scriptHash) {
    if (options.version != null)
      return Script.createWitnessProgram(options.version, options.scriptHash);
    return Script.createScripthash(options.scriptHash);
  }

  return new Script();
};

/**
 * "Guess" whether the input script is pay-to-pubkey.
 * This method is not 100% reliable.
 * @returns {Boolean}
 */

Script.prototype.isPubkeyInput = function isPubkeyInput() {
  if (this.raw.length < 10)
    return false;
  if (this.raw.length > 78)
    return false;
  if (this.raw[0] > opcodes.OP_PUSHDATA4)
    return false;
  return this.code.length === 1 && Script.isSignature(this.code[0].data);
};

/**
 * "Guess" whether the input script is pay-to-pubkeyhash.
 * This method is not 100% reliable.
 * @returns {Boolean}
 */

Script.prototype.isPubkeyhashInput = function isPubkeyhashInput() {
  if (this.raw.length < 44)
    return false;
  if (this.raw.length > 148)
    return false;
  if (this.raw[0] > opcodes.OP_PUSHDATA4)
    return false;
  return this.code.length === 2
    && Script.isSignature(this.code[0].data)
    && Script.isKey(this.code[1].data);
};

/**
 * "Guess" whether the input script is pay-to-multisig.
 * This method is not 100% reliable.
 * @returns {Boolean}
 */

Script.prototype.isMultisigInput = function isMultisigInput() {
  var i;

  if (this.raw.length < 20)
    return false;

  if (this.raw[0] !== opcodes.OP_0)
    return false;

  if (this.raw[1] > opcodes.OP_PUSHDATA4)
    return false;

  // We need to rule out scripthash
  // because it may look like multisig.
  if (this.isScripthashInput())
    return false;

  if (this.code.length < 3)
    return false;

  if (this.code[0].value !== opcodes.OP_0)
    return false;

  for (i = 1; i < this.code.length; i++) {
    if (!Script.isSignature(this.code[i].data))
      return false;
  }

  return true;
};

/**
 * "Guess" whether the input script is pay-to-scripthash.
 * This method is not 100% reliable.
 * @returns {Boolean}
 */

Script.prototype.isScripthashInput = function isScripthashInput() {
  var raw;

  if (this.raw.length < 2)
    return false;

  // Grab the raw redeem script.
  raw = this.code[this.code.length - 1].data;

  // Last data element should be an array
  // for the redeem script.
  if (!Buffer.isBuffer(raw))
    return false;

  // Testing for scripthash inputs requires
  // some evil magic to work. We do it by
  // ruling things _out_. This test will not
  // be correct 100% of the time. We rule
  // out that the last data element is: a
  // null dummy, a valid signature, a valid
  // key, and we ensure that it is at least
  // a script that does not use undefined
  // opcodes.
  if (Script.isDummy(raw))
    return false;

  if (Script.isSignatureEncoding(raw))
    return false;

  if (Script.isKeyEncoding(raw))
    return false;

  if (!Script.isCode(raw))
    return false;

  return true;
};

/**
 * Get coinbase height.
 * @returns {Number} `-1` if not present.
 */

Script.prototype.getCoinbaseHeight = function getCoinbaseHeight() {
  return Script.getCoinbaseHeight(this.raw);
};

/**
 * Get coinbase height.
 * @param {Buffer} raw - Raw script.
 * @returns {Number} `-1` if not present.
 */

Script.getCoinbaseHeight = function getCoinbaseHeight(raw) {
  var flags = constants.flags.STANDARD_VERIFY_FLAGS;
  var data, height, op;

  if (raw.length === 0)
    return -1;

  // Small ints are allowed.
  height = Script.getSmall(raw[0]);

  if (height !== -1)
    return height;

  // No more than 6 bytes (we can't
  // handle 7 byte JS numbers and
  // height 281 trillion is far away).
  if (raw[0] > 0x06)
    return -1;

  // No bad pushes allowed.
  if (raw.length < 1 + raw[0])
    return -1;

  data = raw.slice(1, 1 + raw[0]);

  // Deserialize the height.
  try {
    height = Script.num(data, flags, 6);
  } catch (e) {
    return -1;
  }

  // Reserialize the height.
  op = Opcode.fromNumber(height);

  // Should have been OP_0-OP_16.
  if (!op.data)
    return -1;

  // Ensure the miner serialized the
  // number in the most minimal fashion.
  if (!utils.equal(data, op.data))
    return -1;

  return height.toNumber();
};

/**
 * Get info about a coinbase script.
 * @returns {Object} Object containing `height`,
 * `extraNonce`, `flags`, and `text`.
 */

Script.prototype.getCoinbaseFlags = function getCoinbaseFlags() {
  var index = 0;
  var height = this.getCoinbaseHeight();
  var extraNonce, flags, text;

  if (height !== -1)
    index++;

  if (this.code[1].data && this.code[1].data.length <= 6)
    extraNonce = new bn(this.code[1].data, 'le').toNumber();
  else
    extraNonce = this.getSmall(1);

  flags = Script.encode(this.code.slice(index));

  text = flags.toString('utf8');
  text = text.replace(/[\u0000-\u0019\u007f-\u00ff]/g, '');

  return {
    height: height,
    extraNonce: extraNonce,
    flags: flags,
    text: text
  };
};

/**
 * Test the script against a bloom filter.
 * @param {Bloom} filter
 * @returns {Boolean}
 */

Script.prototype.test = function test(filter) {
  var i, op;

  for (i = 0; i < this.code.length; i++) {
    op = this.code[i];

    if (op.value === -1)
      break;

    if (!op.data || op.data.length === 0)
      continue;

    if (filter.test(op.data))
      return true;
  }

  return false;
};

/**
 * Unshift an item onto the `code` array.
 * @param {Number|String|BN|Buffer} data
 * @returns {Number} Length.
 */

Script.prototype.unshift = function unshift(data) {
  return this.code.unshift(Opcode.from(data));
};

/**
 * Push an item onto the `code` array.
 * @param {Number|String|BN|Buffer} data
 * @returns {Number} Length.
 */

Script.prototype.push = function push(data) {
  return this.code.push(Opcode.from(data));
};

/**
 * Shift an item off of the `code` array.
 * @returns {Buffer|Number}
 */

Script.prototype.shift = function shift() {
  var op = this.code.shift();
  if (!op)
    return;
  return op.data || op.value;
};

/**
 * Pop an item off of the `code` array.
 * @returns {Buffer|Number}
 */

Script.prototype.pop = function push(data) {
  var op = this.code.pop();
  if (!op)
    return;
  return op.data || op.value;
};

/**
 * Remove an item from the `code` array.
 * @param {Number} index
 * @returns {Buffer|Number}
 */

Script.prototype.remove = function remove(i) {
  var op = this.code.splice(i, 1)[0];
  if (!op)
    return;
  return op.data || op.value;
};

/**
 * Insert an item into the `code` array.
 * @param {Number} index
 * @param {Number|String|BN|Buffer} data
 */

Script.prototype.insert = function insert(i, data) {
  assert(i <= this.code.length, 'Index out of bounds.');
  this.code.splice(i, 0, Opcode.from(data))[0];
};

/**
 * Get an item from the `code` array.
 * @param {Number} index
 * @returns {Buffer|Number}
 */

Script.prototype.get = function get(i) {
  var op = this.code[i];
  if (!op)
    return;
  return op.data || op.value;
};

/**
 * Get a small integer from an opcode (OP_0-OP_16).
 * @param {Number} index
 * @returns {Number}
 */

Script.prototype.getSmall = function getSmall(i) {
  var op = this.code[i];
  if (!op)
    return -1;
  return Script.getSmall(op.value);
};

/**
 * Get a number from the `code` array (5-byte limit).
 * @params {Number} index
 * @returns {BN}
 */

Script.prototype.getNumber = function getNumber(i) {
  var small = this.getSmall(i);
  var op = this.code[i];

  if (small !== -1)
    return new bn(small);

  if (!op || !op.data || op.data.length > 5)
    return;

  return Script.num(op.data, constants.flags.VERIFY_NONE, 5);
};

/**
 * Get a string from the `code` array (utf8).
 * @params {Number} index
 * @returns {String}
 */

Script.prototype.getString = function getString(i) {
  var op = this.code[i];
  if (!op || !op.data)
    return;
  return op.data.toString('utf8');
};

/**
 * Set an item in the `code` array.
 * @param {Number} index
 * @param {Buffer|Number|String|BN} data
 */

Script.prototype.set = function set(i, data) {
  assert(i <= this.code.length, 'Index out of bounds.');
  this.code[i] = Opcode.from(data);
};

Script.prototype.__defineGetter__('length', function() {
  return this.code.length;
});

Script.prototype.__defineSetter__('length', function(len) {
  return this.code.length = len;
});

/**
 * Test whether the data element is a ripemd160 hash.
 * @param {Buffer?} hash
 * @returns {Boolean}
 */

Script.isHash = function isHash(hash) {
  return Buffer.isBuffer(hash) && hash.length === 20;
};

/**
 * Test whether the data element is a public key. Note that
 * this does not verify the format of the key, only the length.
 * @param {Buffer?} key
 * @returns {Boolean}
 */

Script.isKey = function isKey(key) {
  return Buffer.isBuffer(key) && key.length >= 33 && key.length <= 65;
};

/**
 * Test whether the data element is a signature. Note that
 * this does not verify the format of the signature, only the length.
 * @param {Buffer?} sig
 * @returns {Boolean}
 */

Script.isSignature = function isSignature(sig) {
  return Buffer.isBuffer(sig) && sig.length >= 9 && sig.length <= 73;
};

/**
 * Test whether the data element is a null dummy (a zero-length array).
 * @param {Buffer?} data
 * @returns {Boolean}
 */

Script.isDummy = function isDummy(data) {
  return Buffer.isBuffer(data) && data.length === 0;
};

/**
 * Test whether the data element is a valid key if VERIFY_STRICTENC is enabled.
 * @param {Buffer} key
 * @param {VerifyFlags?} flags
 * @returns {Boolean}
 * @throws {ScriptError}
 */

Script.validateKey = function validateKey(key, flags) {
  if (flags == null)
    flags = constants.flags.STANDARD_VERIFY_FLAGS;

  if (!Buffer.isBuffer(key))
    throw new ScriptError('BAD_OPCODE');

  if (flags & constants.flags.VERIFY_STRICTENC) {
    if (!Script.isKeyEncoding(key))
      throw new ScriptError('PUBKEYTYPE');
  }

  return true;
};

/**
 * Test whether the data element is a valid key.
 * @param {Buffer} key
 * @returns {Boolean}
 */

Script.isKeyEncoding = function isKeyEncoding(key) {
  if (!Buffer.isBuffer(key))
    return false;

  if (key.length < 33)
    return false;

  if (key[0] === 0x04) {
    if (key.length !== 65)
      return false;
  } else if (key[0] === 0x02 || key[0] === 0x03) {
    if (key.length !== 33)
      return false;
  } else {
    return false;
  }

  return true;
};

/**
 * Test whether the data element is a valid signature based
 * on the encoding, S value, and sighash type. Requires
 * VERIFY_DERSIG|VERIFY_LOW_S|VERIFY_STRICTENC, VERIFY_LOW_S
 * and VERIFY_STRING_ENC to be enabled respectively. Note that
 * this will allow zero-length signatures.
 * @param {Buffer} sig
 * @param {VerifyFlags?} flags
 * @returns {Boolean}
 * @throws {ScriptError}
 */

Script.validateSignature = function validateSignature(sig, flags) {
  if (flags == null)
    flags = constants.flags.STANDARD_VERIFY_FLAGS;

  if (!Buffer.isBuffer(sig))
    throw new ScriptError('BAD_OPCODE');

  // Allow empty sigs
  if (sig.length === 0)
    return true;

  if ((flags & constants.flags.VERIFY_DERSIG)
      || (flags & constants.flags.VERIFY_LOW_S)
      || (flags & constants.flags.VERIFY_STRICTENC)) {
    if (!Script.isSignatureEncoding(sig))
      throw new ScriptError('SIG_DER');
  }

  if (flags & constants.flags.VERIFY_LOW_S) {
    if (!Script.isLowDER(sig))
      throw new ScriptError('SIG_HIGH_S');
  }

  if (flags & constants.flags.VERIFY_STRICTENC) {
    if (!Script.isHashType(sig))
      throw new ScriptError('SIG_HASHTYPE');
  }

  return true;
};

/**
 * Test a signature to see if it abides by BIP66.
 * @see https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki
 * @param {Buffer} sig
 * @returns {Boolean}
 */

Script.isSignatureEncoding = function isSignatureEncoding(sig) {
  var lenR, lenS;

  if (!Buffer.isBuffer(sig))
    return false;

  // Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash]
  // * total-length: 1-byte length descriptor of everything that follows,
  //   excluding the sighash byte.
  // * R-length: 1-byte length descriptor of the R value that follows.
  // * R: arbitrary-length big-endian encoded R value. It must use the shortest
  //   possible encoding for a positive integers (which means no null bytes at
  //   the start, except a single one when the next byte has its highest bit set).
  // * S-length: 1-byte length descriptor of the S value that follows.
  // * S: arbitrary-length big-endian encoded S value. The same rules apply.
  // * sighash: 1-byte value indicating what data is hashed (not part of the DER
  //   signature)

  // Minimum and maximum size constraints.
  if (sig.length < 9)
    return false;

  if (sig.length > 73)
    return false;

  // A signature is of type 0x30 (compound).
  if (sig[0] !== 0x30)
    return false;

  // Make sure the length covers the entire signature.
  if (sig[1] !== sig.length - 3)
    return false;

  // Extract the length of the R element.
  lenR = sig[3];

  // Make sure the length of the S element is still inside the signature.
  if (5 + lenR >= sig.length)
    return false;

  // Extract the length of the S element.
  lenS = sig[5 + lenR];

  // Verify that the length of the signature matches the sum of the length
  // of the elements.
  if (lenR + lenS + 7 !== sig.length)
    return false;

  // Check whether the R element is an integer.
  if (sig[2] !== 0x02)
    return false;

  // Zero-length integers are not allowed for R.
  if (lenR === 0)
    return false;

  // Negative numbers are not allowed for R.
  if (sig[4] & 0x80)
    return false;

  // Null bytes at the start of R are not allowed, unless R would
  // otherwise be interpreted as a negative number.
  if (lenR > 1 && (sig[4] === 0x00) && !(sig[5] & 0x80))
    return false;

  // Check whether the S element is an integer.
  if (sig[lenR + 4] !== 0x02)
    return false;

  // Zero-length integers are not allowed for S.
  if (lenS === 0)
    return false;

  // Negative numbers are not allowed for S.
  if (sig[lenR + 6] & 0x80)
    return false;

  // Null bytes at the start of S are not allowed, unless S would otherwise be
  // interpreted as a negative number.
  if (lenS > 1 && (sig[lenR + 6] === 0x00) && !(sig[lenR + 7] & 0x80))
    return false;

  return true;
};

/**
 * Test a signature to see whether it contains a valid sighash type.
 * @param {Buffer} sig
 * @returns {Boolean}
 */

Script.isHashType = function isHashType(sig) {
  var type;

  if (!Buffer.isBuffer(sig))
    return false;

  if (sig.length === 0)
    return false;

  type = sig[sig.length - 1] & ~constants.hashType.ANYONECANPAY;

  if (!constants.hashTypeByVal[type])
    return false;

  return true;
};

/**
 * Test a signature to see whether it contains a low S value.
 * @param {Buffer} sig
 * @returns {Boolean}
 */

Script.isLowDER = function isLowDER(sig) {
  if (!sig.s) {
    if (!Buffer.isBuffer(sig))
      return false;

    if (!Script.isSignatureEncoding(sig))
      return false;

    sig = sig.slice(0, -1);
  }

  return bcoin.ec.isLowS(sig);
};

/**
 * Format script code into a human readable-string.
 * @param {Array} code
 * @returns {String} Human-readable string.
 */

Script.format = function format(code) {
  var out = [];
  var i, op, data, value, size;

  for (i = 0; i < code.length; i++) {
    op = code[i];
    data = op.data;
    value = op.value;

    if (data) {
      size = data.length.toString(16);

      while (size.length % 2 !== 0)
        size = '0' + size;

      if (!constants.opcodesByVal[value]) {
        value = value.toString(16);
        if (value.length < 2)
          value = '0' + value;
        value = '0x' + value + ' 0x' + data.toString('hex');
        out.push(value);
        continue;
      }

      value = constants.opcodesByVal[value];
      value = value + ' 0x' + size + ' 0x' + data.toString('hex');
      out.push(value);
      continue;
    }

    assert(typeof value === 'number');

    if (constants.opcodesByVal[value]) {
      value = constants.opcodesByVal[value];
      out.push(value);
      continue;
    }

    value = value.toString(16);

    if (value.length < 2)
      value = '0' + value;

    value = '0x' + value;
    out.push(value);
  }

  return out.join(' ');
};

/**
 * Format script code into bitcoind asm format.
 * @param {Array} code
 * @param {Boolean?} decode - Attempt to decode hash types.
 * @returns {String} Human-readable string.
 */

Script.formatASM = function formatASM(code, decode) {
  var out = [];
  var i, op, type, symbol, data, value;

  for (i = 0; i < code.length; i++) {
    op = code[i];
    data = op.data;
    value = op.value;

    if (value === -1) {
      out.push('[error]');
      break;
    }

    if (data) {
      if (data.length <= 4) {
        data = Script.num(data, constants.flags.VERIFY_NONE);
        out.push(data.toString(10));
        continue;
      }

      if (decode && code[0] !== opcodes.OP_RETURN) {
        symbol = '';
        if (Script.isSignatureEncoding(data)) {
          type = data[data.length - 1];
          symbol = constants.hashTypeByVal[type & 0x1f] || '';
          if (symbol) {
            if (type & constants.hashType.ANYONECANPAY)
              symbol += '|ANYONECANPAY';
            symbol = '[' + symbol + ']';
          }
          data = data.slice(0, -1);
        }
        out.push(data.toString('hex') + symbol);
        continue;
      }

      out.push(data.toString('hex'));
      continue;
    }

    value = constants.opcodesByVal[value] || 'OP_UNKNOWN';

    out.push(value);
  }

  return out.join(' ');
};

/**
 * Test the script to see if it contains only push ops.
 * Push ops are: OP_1NEGATE, OP_0-OP_16 and all PUSHDATAs.
 * @returns {Boolean}
 */

Script.prototype.isPushOnly = function isPushOnly() {
  var i, op;

  for (i = 0; i < this.code.length; i++) {
    op = this.code[i];

    if (op.data)
      continue;

    if (op.value == -1)
      return false;

    if (op.value > opcodes.OP_16)
      return false;
  }

  return true;
};

/**
 * Count the sigops in the script.
 * @param {Boolean} accurate - Whether to enable accurate counting. This will
 * take into account the `n` value for OP_CHECKMULTISIG(VERIFY).
 * @returns {Number} sigop count
 */

Script.prototype.getSigops = function getSigops(accurate) {
  var total = 0;
  var lastOp = -1;
  var i, op;

  for (i = 0; i < this.code.length; i++) {
    op = this.code[i];

    if (op.data)
      continue;

    if (op.value === -1)
      break;

    switch (op.value) {
      case opcodes.OP_CHECKSIG:
      case opcodes.OP_CHECKSIGVERIFY:
        total++;
        break;
      case opcodes.OP_CHECKMULTISIG:
      case opcodes.OP_CHECKMULTISIGVERIFY:
        if (accurate && lastOp >= opcodes.OP_1 && lastOp <= opcodes.OP_16)
          total += lastOp - 0x50;
        else
          total += constants.script.MAX_MULTISIG_PUBKEYS;
        break;
    }

    lastOp = op.value;
  }

  return total;
};

/**
 * Count the sigops in the script, taking into account redeem scripts.
 * @param {Script} input - Input script, needed for access to redeem script.
 * @returns {Number} sigop count
 */

Script.prototype.getScripthashSigops = function getScripthashSigops(input) {
  var i, op, redeem;

  if (!this.isScripthash())
    return this.getSigops(true);

  for (i = 0; i < input.code.length; i++) {
    op = input.code[i];

    if (op.data)
      continue;

    if (op.value === -1)
      return 0;

    if (op.value > opcodes.OP_16)
      return 0;
  }

  if (!op.data)
    return 0;

  redeem = new Script(op.data);

  return redeem.getSigops(true);
};

/**
 * Count the sigops for a program.
 * @param {Program} program
 * @param {Witness} witness
 * @param {VerifyFlags} flags
 * @returns {Number} sigop count
 */

Script.witnessSigops = function witnessSigops(program, witness, flags) {
  var redeem;

  if (flags == null)
    flags = constants.flags.STANDARD_VERIFY_FLAGS;

  if (program.version === 0) {
    if (program.data.length === 20)
      return 1;

    if (program.data.length === 32 && witness.items.length > 0) {
      redeem = witness.getRedeem();
      return redeem.getSigops(true);
    }
  }

  return 0;
};

/**
 * Count the sigops in a script, taking into account witness programs.
 * @param {Script} input
 * @param {Script} output
 * @param {Witness} witness
 * @param {VerifyFlags} flags
 * @returns {Number} sigop count
 */

Script.getWitnessSigops = function getWitnessSigops(input, output, witness, flags) {
  var redeem;

  if (flags == null)
    flags = constants.flags.STANDARD_VERIFY_FLAGS;

  if ((flags & constants.flags.VERIFY_WITNESS) === 0)
    return 0;

  assert((flags & constants.flags.VERIFY_P2SH) !== 0);

  if (output.isWitnessProgram())
    return Script.witnessSigops(output.getWitnessProgram(), witness, flags);

  // This is a unique situation in terms of consensus
  // rules. We can just grab the redeem script without
  // "parsing" (i.e. checking for pushdata parse errors)
  // the script. This is because isPushOnly is called
  // which checks for parse errors and will return
  // false if one is found. Even the bitcoind code
  // does not check the return value of GetOp.
  if (output.isScripthash() && input.isPushOnly()) {
    redeem = input.getRedeem();
    if (redeem && redeem.isWitnessProgram())
      return Script.witnessSigops(redeem.getWitnessProgram(), witness, flags);
  }

  return 0;
};

/**
 * Parse a bitcoind test script
 * string into a script object.
 * @param {String} items - Script string.
 * @returns {Script}
 * @throws Parse error.
 */

Script.fromString = function fromString(code) {
  var i, op, symbol, p;

  if (typeof code !== 'string')
    return new Script();

  code = code.trim();

  if (code.length === 0)
    return new Script();

  code = code.split(/\s+/);
  p = new BufferWriter();

  for (i = 0; i < code.length; i++) {
    op = code[i];

    symbol = op.toUpperCase();
    if (symbol.indexOf('OP_') !== 0)
      symbol = 'OP_' + symbol;

    if (opcodes[symbol] == null) {
      if (op[0] === '\'') {
        assert(op[op.length - 1] === '\'', 'Unknown opcode.');
        op = op.slice(1, -1);
        op = Opcode.fromString(op);
        p.writeBytes(op.toRaw());
        continue;
      }
      if (/^-?\d+$/.test(op)) {
        op = new bn(op, 10);
        op = Opcode.fromNumber(op);
        p.writeBytes(op.toRaw());
        continue;
      }
      assert(op.indexOf('0x') === 0, 'Unknown opcode.');
      op = op.substring(2);
      assert(utils.isHex(op), 'Unknown opcode.');
      op = new Buffer(op, 'hex');
      p.writeBytes(op);
      continue;
    }

    p.writeU8(opcodes[symbol]);
  }

  return new Script(p.render());
};

/**
 * Get a small integer from an opcode (OP_0-OP_16).
 * @param {Number} index
 * @returns {Number}
 */

Script.getSmall = function getSmall(op) {
  if (typeof op !== 'number')
    return -1;

  if (op === opcodes.OP_0)
    return 0;

  if (op >= opcodes.OP_1 && op <= opcodes.OP_16)
    return op - 0x50;

  return -1;
};

/**
 * Convert a number to a small integer (OP_0-OP_16).
 * @param {Number} num
 * @returns {Number} opcode
 */

Script.toSmall = function toSmall(op) {
  assert(op >= 0 && op <= 16);

  if (op === 0)
    return opcodes.OP_0;

  return op + 0x50;
};

/**
 * Verify an input and output script, and a witness if present.
 * @param {Script} input
 * @param {Witness} witness
 * @param {Script} output
 * @param {TX} tx
 * @param {Number} i
 * @param {VerifyFlags} flags
 * @returns {Boolean}
 * @throws {ScriptError}
 */

Script.verify = function verify(input, witness, output, tx, i, flags) {
  var copy, raw, redeem, hadWitness;
  var stack = new Stack();

  if (flags == null)
    flags = constants.flags.STANDARD_VERIFY_FLAGS;

  if (flags & constants.flags.VERIFY_SIGPUSHONLY) {
    if (!input.isPushOnly())
      throw new ScriptError('SIG_PUSHONLY');
  }

  // Execute the input script
  input.execute(stack, flags, tx, i, 0);

  // Copy the stack for P2SH
  if (flags & constants.flags.VERIFY_P2SH)
    copy = stack.clone();

  // Execute the previous output script
  output.execute(stack, flags, tx, i, 0);

  // Verify the script did not fail as well as the stack values
  if (stack.length === 0 || !Script.bool(stack.pop()))
    throw new ScriptError('EVAL_FALSE');

  if ((flags & constants.flags.VERIFY_WITNESS) && output.isWitnessProgram()) {
    hadWitness = true;

    // Input script must be empty.
    if (input.raw.length !== 0)
      throw new ScriptError('WITNESS_MALLEATED');

    // Verify the program in the output script
    Script.verifyProgram(witness, output, flags, tx, i);

    // Force a cleanstack
    stack.length = 0;
  }

  // If the script is P2SH, execute the real output script
  if ((flags & constants.flags.VERIFY_P2SH) && output.isScripthash()) {
    // P2SH can only have push ops in the scriptSig
    if (!input.isPushOnly())
      throw new ScriptError('SIG_PUSHONLY');

    // Reset the stack
    stack = copy;

    // Stack should not be empty at this point
    if (stack.length === 0)
      throw new ScriptError('EVAL_FALSE');

    // Grab the real redeem script
    raw = stack.pop();
    redeem = new Script(raw);

    // Execute the redeem script
    redeem.execute(stack, flags, tx, i, 0);

    // Verify the script did not fail as well as the stack values
    if (stack.length === 0 || !Script.bool(stack.pop()))
      throw new ScriptError('EVAL_FALSE');

    if ((flags & constants.flags.VERIFY_WITNESS) && redeem.isWitnessProgram()) {
      hadWitness = true;

      // Input script must be exactly one push of the redeem script.
      if (!utils.equal(input.raw, Opcode.fromPush(raw).toRaw()))
        throw new ScriptError('WITNESS_MALLEATED_P2SH');

      // Verify the program in the redeem script
      Script.verifyProgram(witness, redeem, flags, tx, i);

      // Force a cleanstack
      stack.length = 0;
    }
  }

  // Ensure there is nothing left on the stack
  if (flags & constants.flags.VERIFY_CLEANSTACK) {
    assert((flags & constants.flags.VERIFY_P2SH) !== 0);
    // assert((flags & constants.flags.VERIFY_WITNESS) !== 0);
    if (stack.length !== 0)
      throw new ScriptError('CLEANSTACK');
  }

  // If we had a witness but no witness program, fail.
  if (flags & constants.flags.VERIFY_WITNESS) {
    assert((flags & constants.flags.VERIFY_P2SH) !== 0);
    if (!hadWitness && witness.items.length > 0)
      throw new ScriptError('WITNESS_UNEXPECTED');
  }

  return true;
};

/**
 * Verify a witness program. This runs after regular script
 * execution if a witness program is present. It will convert
 * the witness to a stack and execute the program.
 * @param {Witness} witness
 * @param {Script} output
 * @param {VerifyFlags} flags
 * @param {TX} tx
 * @param {Number} i
 * @throws {ScriptError}
 */

Script.verifyProgram = function verifyProgram(witness, output, flags, tx, i) {
  var program = output.getWitnessProgram();
  var stack = witness.toStack();
  var witnessScript, redeem, j;

  assert(program, 'verifyProgram called on non-witness-program.');
  assert((flags & constants.flags.VERIFY_WITNESS) !== 0);

  if (program.version === 0) {
    if (program.data.length === 32) {
      if (stack.length === 0)
        throw new ScriptError('WITNESS_PROGRAM_WITNESS_EMPTY');

      witnessScript = stack.pop();

      if (!utils.equal(utils.sha256(witnessScript), program.data))
        throw new ScriptError('WITNESS_PROGRAM_MISMATCH');

      redeem = new Script(witnessScript);
    } else if (program.data.length === 20) {
      if (stack.length !== 2)
        throw new ScriptError('WITNESS_PROGRAM_MISMATCH');

      redeem = Script.createPubkeyhash(program.data);
    } else {
      // Failure on version=0 (bad program data length)
      throw new ScriptError('WITNESS_PROGRAM_WRONG_LENGTH');
    }
  } else {
    // Anyone can spend (we can return true here
    // if we want to always relay these transactions).
    // Otherwise, if we want to act like an "old"
    // implementation and only accept them in blocks,
    // we can use the regalar output script which will
    // succeed in a block, but fail in the mempool
    // due to VERIFY_CLEANSTACK.
    if (flags & constants.flags.VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM)
      throw new ScriptError('DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM');
    return true;
  }

  for (j = 0; j < stack.length; j++) {
    if (stack.get(j).length > constants.script.MAX_PUSH)
      throw new ScriptError('PUSH_SIZE');
  }

  redeem.execute(stack, flags, tx, i, 1);

  // Verify the script did not fail as well as the stack values
  if (stack.length !== 1 || !Script.bool(stack.pop()))
    throw new ScriptError('EVAL_FALSE');

  return true;
};

/**
 * Verify a signature, taking into account sighash type
 * and whether the signature is historical.
 * @param {Buffer} msg - Signature hash.
 * @param {Buffer} sig
 * @param {Buffer} key
 * @param {VerifyFlags?} flags - If none of VERIFY_DERSIG,
 * VERIFY_LOW_S, or VERIFY_STRICTENC are enabled, the signature
 * is treated as historical, allowing odd signature lengths
 * and high S values.
 * @returns {Boolean}
 */

Script.checksig = function checksig(msg, sig, key, flags) {
  var historical = false;
  var high = false;

  if (flags == null)
    flags = constants.flags.STANDARD_VERIFY_FLAGS;

  if (!Buffer.isBuffer(sig))
    return false;

  // Attempt to normalize the signature
  // length before passing to elliptic.
  // Note: We only do this for historical data!
  // https://github.com/indutny/elliptic/issues/78
  if (!((flags & constants.flags.VERIFY_DERSIG)
      || (flags & constants.flags.VERIFY_LOW_S)
      || (flags & constants.flags.VERIFY_STRICTENC))) {
    historical = true;
  }

  if (!(flags & constants.flags.VERIFY_LOW_S))
    high = true;

  return bcoin.ec.verify(msg, sig.slice(0, -1), key, historical, high);
};

/**
 * Sign a message, appending the sighash type.
 * @param {Buffer} msg - Signature hash.
 * @param {Buffer} key - Public key.
 * @param {Number} type - Sighash type.
 * @returns {Buffer} signature
 */

Script.sign = function sign(msg, key, type) {
  var sig = bcoin.ec.sign(msg, key);
  var p = new BufferWriter();

  // Add the sighash type as a single byte
  // to the signature.
  p.writeBytes(sig);
  p.writeU8(type);

  return p.render();
};

/**
 * Parse a serialized script, returning the "naked"
 * representation of a Script object (the same
 * properties, but it is not instantiated -- suitable
 * as an options object for Script).
 * @param {Buffer|String} data - Serialized script.
 * @param {String?} enc - Either `"hex"` or `null`.
 * @returns {Object} Naked script object.
 */

Script.parseRaw = function parseRaw(data, enc) {
  if (enc === 'hex')
    data = new Buffer(data, 'hex');

  return {
    raw: data
  };
};

/**
 * Create a script from a serialized buffer.
 * @param {Buffer|String} data - Serialized script.
 * @param {String?} enc - Either `"hex"` or `null`.
 * @returns {Script}
 */

Script.fromRaw = function fromRaw(data, enc) {
  return new Script(Script.parseRaw(data, enc));
};

/**
 * Decode a serialized script into script code.
 * Note that the serialized script must _not_
 * include the varint size before it. Parse
 * errors will output an opcode with a value
 * of -1.
 *
 * @param {Buffer} raw - Serialized script.
 * @returns {Opcode[]} Script code.
 */

Script.decode = function decode(raw) {
  var p = new BufferReader(raw, true);
  var code = [];
  var op, size, data;

  assert(Buffer.isBuffer(raw));

  while (p.left()) {
    op = p.readU8();
    if (op >= 0x01 && op <= 0x4b) {
      if (p.left() < op) {
        code.push(new Opcode(-1));
        continue;
      }
      data = p.readBytes(op);
      code.push(new Opcode(op, data));
    } else if (op === opcodes.OP_PUSHDATA1) {
      if (p.left() < 1) {
        code.push(new Opcode(-1));
        continue;
      }
      size = p.readU8();
      if (p.left() < size) {
        code.push(new Opcode(-1));
        continue;
      }
      data = p.readBytes(size);
      code.push(new Opcode(op, data));
    } else if (op === opcodes.OP_PUSHDATA2) {
      if (p.left() < 2) {
        code.push(new Opcode(-1));
        continue;
      }
      size = p.readU16();
      if (p.left() < size) {
        code.push(new Opcode(-1));
        continue;
      }
      data = p.readBytes(size);
      code.push(new Opcode(op, data));
    } else if (op === opcodes.OP_PUSHDATA4) {
      if (p.left() < 4) {
        code.push(new Opcode(-1));
        continue;
      }
      size = p.readU32();
      if (p.left() < size) {
        code.push(new Opcode(-1));
        continue;
      }
      data = p.readBytes(size);
      code.push(new Opcode(op, data));
    } else {
      code.push(new Opcode(op));
    }
  }

  return code;
};

/**
 * Encode and serialize script code. This will _not_
 * include the varint size at the start.
 * @param {Array} code - Script code.
 * @returns {Buffer} Serialized script.
 */

Script.encode = function encode(code, writer) {
  var p = new BufferWriter(writer);
  var i, op;

  for (i = 0; i < code.length; i++) {
    op = code[i];

    if (op.value === -1)
      throw new Error('Cannot reserialize a parse error.');

    if (op.data) {
      if (op.value <= 0x4b) {
        p.writeU8(op.data.length);
        p.writeBytes(op.data);
      } else if (op.value === opcodes.OP_PUSHDATA1) {
        p.writeU8(opcodes.OP_PUSHDATA1);
        p.writeU8(op.data.length);
        p.writeBytes(op.data);
      } else if (op.value === opcodes.OP_PUSHDATA2) {
        p.writeU8(opcodes.OP_PUSHDATA2);
        p.writeU16(op.data.length);
        p.writeBytes(op.data);
      } else if (op.value === opcodes.OP_PUSHDATA4) {
        p.writeU8(opcodes.OP_PUSHDATA4);
        p.writeU32(op.data.length);
        p.writeBytes(op.data);
      } else {
        throw new Error('Unknown pushdata opcode.');
      }
      continue;
    }

    p.writeU8(op.value);
  }

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Convert an array of Buffers and
 * Numbers into an array of Opcodes.
 * @param {Array} code
 * @returns {Opcode[]}
 */

Script.parseArray = function parseArray(code) {
  var out = [];
  var i, op;

  if (code[0] instanceof Opcode)
    return code;

  for (i = 0; i < code.length; i++) {
    op = code[i];
    if (Buffer.isBuffer(op)) {
      out.push(Opcode.fromData(op));
      continue;
    }
    assert(typeof op === 'number');
    out.push(new Opcode(op));
  }

  return out;
};

/**
 * Calculate the size (including
 * the opcode) of a pushdata.
 * @param {Number} num - Pushdata data length.
 * @returns {Number} size
 */

Script.sizePush = function sizePush(num) {
  if (num <= 0x4b)
    return 1;

  if (num <= 0xff)
    return 2;

  if (num <= 0xffff)
    return 3;

  return 5;
};

/**
 * Test whether an object a Script.
 * @param {Object} obj
 * @returns {Boolean}
 */

Script.isScript = function isScript(obj) {
  return obj
    && Buffer.isBuffer(obj.raw)
    && typeof obj.getSubscript === 'function';
};

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
  return Script.encode([this]);
};

/**
 * Instantiate an opcode from a number.
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
  return Opcode.fromData(Script.array(num));
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

  if (bn.isBN(data))
    return Opcode.fromNumber(data);

  if (typeof data === 'string')
    return Opcode.fromString(data, 'utf8');

  return Opcode.fromData(data);
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

exports = Script;

exports.opcodes = constants.opcodes;
exports.opcodesByVal = constants.opcodesByVal;

exports.Script = Script;
exports.Opcode = Opcode;
exports.Stack = Stack;
exports.Witness = Witness;

module.exports = exports;
