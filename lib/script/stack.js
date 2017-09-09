/*!
 * stack.js - stack object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const common = require('./common');
const ScriptNum = require('./scriptnum');

/**
 * Represents the stack of a Script during execution.
 * @alias module:script.Stack
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

/*
 * Expose length setter and getter.
 */

Object.defineProperty(Stack.prototype, 'length', {
  get() {
    return this.items.length;
  },
  set(length) {
    this.items.length = length;
    return this.items.length;
  }
});

/**
 * Instantiate a key and value iterator.
 * @returns {StackIterator}
 */

Stack.prototype[Symbol.iterator] = function iterator() {
  return this.items[Symbol.iterator]();
};

/**
 * Instantiate a value-only iterator.
 * @returns {StackIterator}
 */

Stack.prototype.values = function values() {
  return this.items.values();
};

/**
 * Instantiate a key and value iterator.
 * @returns {StackIterator}
 */

Stack.prototype.entries = function entries() {
  return this.items.entries();
};

/**
 * Inspect the stack.
 * @returns {String} Human-readable stack.
 */

Stack.prototype.inspect = function inspect() {
  return `<Stack: ${this.toString()}>`;
};

/**
 * Convert the stack to a string.
 * @returns {String} Human-readable stack.
 */

Stack.prototype.toString = function toString() {
  const out = [];

  for (const item of this.items)
    out.push(item.toString('hex'));

  return out.join(' ');
};

/**
 * Format the stack as bitcoind asm.
 * @param {Boolean?} decode - Attempt to decode hash types.
 * @returns {String} Human-readable script.
 */

Stack.prototype.toASM = function toASM(decode) {
  const out = [];

  for (const item of this.items)
    out.push(common.toASM(item, decode));

  return out.join(' ');
};

/**
 * Clone the stack.
 * @returns {Stack} Cloned stack.
 */

Stack.prototype.clone = function clone() {
  return new Stack(this.items.slice());
};

/**
 * Clear the stack.
 * @returns {Stack}
 */

Stack.prototype.clear = function clear() {
  this.items.length = 0;
  return this;
};

/**
 * Get a stack item by index.
 * @param {Number} index
 * @returns {Buffer|null}
 */

Stack.prototype.get = function get(index) {
  if (index < 0)
    index += this.items.length;

  if (index < 0 || index >= this.items.length)
    return null;

  return this.items[index];
};

/**
 * Pop a stack item.
 * @see Array#pop
 * @returns {Buffer|null}
 */

Stack.prototype.pop = function pop() {
  const item = this.items.pop();
  return item || null;
};

/**
 * Shift a stack item.
 * @see Array#shift
 * @returns {Buffer|null}
 */

Stack.prototype.shift = function shift() {
  const item = this.items.shift();
  return item || null;
};

/**
 * Remove an item.
 * @param {Number} index
 * @returns {Buffer}
 */

Stack.prototype.remove = function remove(index) {
  if (index < 0)
    index += this.items.length;

  if (index < 0 || index >= this.items.length)
    return null;

  const items = this.items.splice(index, 1);

  if (items.length === 0)
    return null;

  return items[0];
};

/**
 * Set stack item at index.
 * @param {Number} index
 * @param {Buffer} value
 * @returns {Buffer}
 */

Stack.prototype.set = function set(index, item) {
  if (index < 0)
    index += this.items.length;

  assert(Buffer.isBuffer(item));
  assert(index >= 0 && index <= this.items.length);

  this.items[index] = item;

  return this;
};

/**
 * Push item onto stack.
 * @see Array#push
 * @param {Buffer} item
 * @returns {Number} Stack size.
 */

Stack.prototype.push = function push(item) {
  assert(Buffer.isBuffer(item));
  this.items.push(item);
  return this;
};

/**
 * Unshift item from stack.
 * @see Array#unshift
 * @param {Buffer} item
 * @returns {Number}
 */

Stack.prototype.unshift = function unshift(item) {
  assert(Buffer.isBuffer(item));
  this.items.unshift(item);
  return this;
};

/**
 * Insert an item.
 * @param {Number} index
 * @param {Buffer} item
 * @returns {Buffer}
 */

Stack.prototype.insert = function insert(index, item) {
  if (index < 0)
    index += this.items.length;

  assert(Buffer.isBuffer(item));
  assert(index >= 0 && index <= this.items.length);

  this.items.splice(index, 0, item);

  return this;
};

/**
 * Erase stack items.
 * @param {Number} start
 * @param {Number} end
 * @returns {Buffer[]}
 */

Stack.prototype.erase = function erase(start, end) {
  if (start < 0)
    start = this.items.length + start;

  if (end < 0)
    end = this.items.length + end;

  this.items.splice(start, end - start);
};

/**
 * Swap stack values.
 * @param {Number} i1 - Index 1.
 * @param {Number} i2 - Index 2.
 */

Stack.prototype.swap = function swap(i1, i2) {
  if (i1 < 0)
    i1 = this.items.length + i1;

  if (i2 < 0)
    i2 = this.items.length + i2;

  const v1 = this.items[i1];
  const v2 = this.items[i2];

  this.items[i1] = v2;
  this.items[i2] = v1;
};

/*
 * Data
 */

Stack.prototype.getData = function getData(index) {
  return this.get(index);
};

Stack.prototype.popData = function popData() {
  return this.pop();
};

Stack.prototype.shiftData = function shiftData() {
  return this.shift();
};

Stack.prototype.removeData = function removeData(index) {
  return this.remove(index);
};

Stack.prototype.setData = function setData(index, data) {
  return this.set(index, data);
};

Stack.prototype.pushData = function pushData(data) {
  return this.push(data);
};

Stack.prototype.unshiftData = function unshiftData(data) {
  return this.unshift(data);
};

Stack.prototype.insertData = function insertData(index, data) {
  return this.insert(index, data);
};

/*
 * Length
 */

Stack.prototype.getLength = function getLength(index) {
  const item = this.get(index);
  return item ? item.length : -1;
};

/*
 * String
 */

Stack.prototype.getString = function getString(index, enc) {
  const item = this.get(index);
  return item ? Stack.toString(item, enc) : null;
};

Stack.prototype.popString = function popString(enc) {
  const item = this.pop();
  return item ? Stack.toString(item, enc) : null;
};

Stack.prototype.shiftString = function shiftString(enc) {
  const item = this.shift();
  return item ? Stack.toString(item, enc) : null;
};

Stack.prototype.removeString = function removeString(index, enc) {
  const item = this.remove(index);
  return item ? Stack.toString(item, enc) : null;
};

Stack.prototype.setString = function setString(index, str, enc) {
  return this.set(index, Stack.fromString(str, enc));
};

Stack.prototype.pushString = function pushString(str, enc) {
  return this.push(Stack.fromString(str, enc));
};

Stack.prototype.unshiftString = function unshiftString(str, enc) {
  return this.unshift(Stack.fromString(str, enc));
};

Stack.prototype.insertString = function insertString(index, str, enc) {
  return this.insert(index, Stack.fromString(str, enc));
};

/*
 * Num
 */

Stack.prototype.getNum = function getNum(index, minimal, limit) {
  const item = this.get(index);
  return item ? Stack.toNum(item, minimal, limit) : null;
};

Stack.prototype.popNum = function popNum(minimal, limit) {
  const item = this.pop();
  return item ? Stack.toNum(item, minimal, limit) : null;
};

Stack.prototype.shiftNum = function shiftNum(minimal, limit) {
  const item = this.shift();
  return item ? Stack.toNum(item, minimal, limit) : null;
};

Stack.prototype.removeNum = function removeNum(index, minimal, limit) {
  const item = this.remove(index);
  return item ? Stack.toNum(item, minimal, limit) : null;
};

Stack.prototype.setNum = function setNum(index, num) {
  return this.set(index, Stack.fromNum(num));
};

Stack.prototype.pushNum = function pushNum(num) {
  return this.push(Stack.fromNum(num));
};

Stack.prototype.unshiftNum = function unshiftNum(num) {
  return this.unshift(Stack.fromNum(num));
};

Stack.prototype.insertNum = function insertNum(index, num) {
  return this.insert(index, Stack.fromNum(num));
};

/*
 * Int
 */

Stack.prototype.getInt = function getInt(index, minimal, limit) {
  const item = this.get(index);
  return item ? Stack.toInt(item, minimal, limit) : -1;
};

Stack.prototype.popInt = function popInt(minimal, limit) {
  const item = this.pop();
  return item ? Stack.toInt(item, minimal, limit) : -1;
};

Stack.prototype.shiftInt = function shiftInt(minimal, limit) {
  const item = this.shift();
  return item ? Stack.toInt(item, minimal, limit) : -1;
};

Stack.prototype.removeInt = function removeInt(index, minimal, limit) {
  const item = this.remove(index);
  return item ? Stack.toInt(item, minimal, limit) : -1;
};

Stack.prototype.setInt = function setInt(index, num) {
  return this.set(index, Stack.fromInt(num));
};

Stack.prototype.pushInt = function pushInt(num) {
  return this.push(Stack.fromInt(num));
};

Stack.prototype.unshiftInt = function unshiftInt(num) {
  return this.unshift(Stack.fromInt(num));
};

Stack.prototype.insertInt = function insertInt(index, num) {
  return this.insert(index, Stack.fromInt(num));
};

/*
 * Bool
 */

Stack.prototype.getBool = function getBool(index) {
  const item = this.get(index);
  return item ? Stack.toBool(item) : false;
};

Stack.prototype.popBool = function popBool() {
  const item = this.pop();
  return item ? Stack.toBool(item) : false;
};

Stack.prototype.shiftBool = function shiftBool() {
  const item = this.shift();
  return item ? Stack.toBool(item) : false;
};

Stack.prototype.removeBool = function removeBool(index) {
  const item = this.remove(index);
  return item ? Stack.toBool(item) : false;
};

Stack.prototype.setBool = function setBool(index, value) {
  return this.set(index, Stack.fromBool(value));
};

Stack.prototype.pushBool = function pushBool(value) {
  return this.push(Stack.fromBool(value));
};

Stack.prototype.unshiftBool = function unshiftBool(value) {
  return this.unshift(Stack.fromBool(value));
};

Stack.prototype.insertBool = function insertBool(index, value) {
  return this.insert(index, Stack.fromBool(value));
};

/**
 * Test an object to see if it is a Stack.
 * @param {Object} obj
 * @returns {Boolean}
 */

Stack.isStack = function isStack(obj) {
  return obj instanceof Stack;
};

/*
 * Encoding
 */

Stack.toString = function toString(item, enc) {
  assert(Buffer.isBuffer(item));
  return item.toString(enc || 'utf8');
};

Stack.fromString = function fromString(str, enc) {
  assert(typeof str === 'string');
  return Buffer.from(str, enc || 'utf8');
};

Stack.toNum = function toNum(item, minimal, limit) {
  return ScriptNum.decode(item, minimal, limit);
};

Stack.fromNum = function fromNum(num) {
  assert(ScriptNum.isScriptNum(num));
  return num.encode();
};

Stack.toInt = function toInt(item, minimal, limit) {
  const num = Stack.toNum(item, minimal, limit);
  return num.getInt();
};

Stack.fromInt = function fromInt(int) {
  assert(typeof int === 'number');

  if (int >= -1 && int <= 16)
    return common.small[int + 1];

  const num = ScriptNum.fromNumber(int);

  return Stack.fromNum(num);
};

Stack.toBool = function toBool(item) {
  assert(Buffer.isBuffer(item));

  for (let i = 0; i < item.length; i++) {
    if (item[i] !== 0) {
      // Cannot be negative zero
      if (i === item.length - 1 && item[i] === 0x80)
        return false;
      return true;
    }
  }

  return false;
};

Stack.fromBool = function fromBool(value) {
  assert(typeof value === 'boolean');
  return Stack.fromInt(value ? 1 : 0);
};

/*
 * Expose
 */

module.exports = Stack;
