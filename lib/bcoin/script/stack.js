/*!
 * stack.js - stack object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var bcoin = require('../env');
var constants = bcoin.constants;
var opcodes = constants.opcodes;
var ScriptError = bcoin.errors.ScriptError;

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

Stack.prototype.__defineGetter__('length', function() {
  return this.items.length;
});

Stack.prototype.__defineSetter__('length', function(length) {
  return this.items.length = length;
});

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
  return bcoin.witness.format(this.items);
};

/**
 * Format the stack as bitcoind asm.
 * @param {Boolean?} decode - Attempt to decode hash types.
 * @returns {String} Human-readable script.
 */

Stack.prototype.toASM = function toASM(decode) {
  return bcoin.script.formatASM(this.items, decode);
};

/**
 * Pop the redeem script off the stack and deserialize it.
 * @returns {Script|null} The redeem script.
 */

Stack.prototype.getRedeem = function getRedeem() {
  var redeem = this.items[this.items.length - 1];
  if (!redeem)
    return;
  return new bcoin.script(redeem);
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
 * Clear the stack.
 */

Stack.prototype.clear = function clear() {
  this.items.length = 0;
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

/**
 * Swap stack values.
 * @private
 * @param {Number} i1 - Index 1.
 * @param {Number} i2 - Index 2.
 */

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

  if (bcoin.script.bool(this.top(-1)))
    this.push(this.top(-1));
};

/**
 * Perform the OP_DEPTH operation.
 * @throws {ScriptError}
 */

Stack.prototype.depth = function depth() {
  this.push(bcoin.script.array(this.length));
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

/**
 * Perform a pick or roll.
 * @private
 * @param {Number} op
 * @param {VerifyFlags} flags
 * @throws {ScriptError}
 */

Stack.prototype._pickroll = function pickroll(op, flags) {
  var val, n;

  if (this.length < 2)
    throw new ScriptError('INVALID_STACK_OPERATION', op);

  val = this.pop();
  n = bcoin.script.num(val, flags).toNumber();

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

  this.push(bcoin.script.array(this.top(-1).length));
};

/**
 * Test an object to see if it is a Stack.
 * @param {Object} obj
 * @returns {Boolean}
 */

Stack.isStack = function isStack(obj) {
  return obj && Array.isArray(obj.items) && typeof obj.swap2 === 'function';
};

/*
 * Expose
 */

module.exports = Stack;
