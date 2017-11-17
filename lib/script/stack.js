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
 * Stack
 * Represents the stack of a Script during execution.
 * @alias module:script.Stack
 * @property {Buffer[]} items - Stack items.
 * @property {Number} length - Size of stack.
 */

class Stack {
  /**
   * Create a stack.
   * @constructor
   * @param {Buffer[]?} items - Stack items.
   */

  constructor(items) {
    this.items = items || [];
  }

  /**
   * Get length.
   * @returns {Number}
   */

  get length() {
    return this.items.length;
  }

  /**
   * Set length.
   * @param {Number} value
   */

  set length(value) {
    this.items.length = value;
  }

  /**
   * Instantiate a value-only iterator.
   * @returns {StackIterator}
   */

  [Symbol.iterator]() {
    return this.items[Symbol.iterator]();
  }

  /**
   * Instantiate a value-only iterator.
   * @returns {StackIterator}
   */

  values() {
    return this.items.values();
  }

  /**
   * Instantiate a key and value iterator.
   * @returns {StackIterator}
   */

  entries() {
    return this.items.entries();
  }

  /**
   * Inspect the stack.
   * @returns {String} Human-readable stack.
   */

  inspect() {
    return `<Stack: ${this.toString()}>`;
  }

  /**
   * Convert the stack to a string.
   * @returns {String} Human-readable stack.
   */

  toString() {
    const out = [];

    for (const item of this.items)
      out.push(item.toString('hex'));

    return out.join(' ');
  }

  /**
   * Format the stack as bitcoind asm.
   * @param {Boolean?} decode - Attempt to decode hash types.
   * @returns {String} Human-readable script.
   */

  toASM(decode) {
    const out = [];

    for (const item of this.items)
      out.push(common.toASM(item, decode));

    return out.join(' ');
  }

  /**
   * Clone the stack.
   * @returns {Stack} Cloned stack.
   */

  clone() {
    return new this.constructor(this.items.slice());
  }

  /**
   * Clear the stack.
   * @returns {Stack}
   */

  clear() {
    this.items.length = 0;
    return this;
  }

  /**
   * Get a stack item by index.
   * @param {Number} index
   * @returns {Buffer|null}
   */

  get(index) {
    if (index < 0)
      index += this.items.length;

    if (index < 0 || index >= this.items.length)
      return null;

    return this.items[index];
  }

  /**
   * Pop a stack item.
   * @see Array#pop
   * @returns {Buffer|null}
   */

  pop() {
    const item = this.items.pop();
    return item || null;
  }

  /**
   * Shift a stack item.
   * @see Array#shift
   * @returns {Buffer|null}
   */

  shift() {
    const item = this.items.shift();
    return item || null;
  }

  /**
   * Remove an item.
   * @param {Number} index
   * @returns {Buffer}
   */

  remove(index) {
    if (index < 0)
      index += this.items.length;

    if (index < 0 || index >= this.items.length)
      return null;

    const items = this.items.splice(index, 1);

    if (items.length === 0)
      return null;

    return items[0];
  }

  /**
   * Set stack item at index.
   * @param {Number} index
   * @param {Buffer} value
   * @returns {Buffer}
   */

  set(index, item) {
    if (index < 0)
      index += this.items.length;

    assert(Buffer.isBuffer(item));
    assert(index >= 0 && index <= this.items.length);

    this.items[index] = item;

    return this;
  }

  /**
   * Push item onto stack.
   * @see Array#push
   * @param {Buffer} item
   * @returns {Number} Stack size.
   */

  push(item) {
    assert(Buffer.isBuffer(item));
    this.items.push(item);
    return this;
  }

  /**
   * Unshift item from stack.
   * @see Array#unshift
   * @param {Buffer} item
   * @returns {Number}
   */

  unshift(item) {
    assert(Buffer.isBuffer(item));
    this.items.unshift(item);
    return this;
  }

  /**
   * Insert an item.
   * @param {Number} index
   * @param {Buffer} item
   * @returns {Buffer}
   */

  insert(index, item) {
    if (index < 0)
      index += this.items.length;

    assert(Buffer.isBuffer(item));
    assert(index >= 0 && index <= this.items.length);

    this.items.splice(index, 0, item);

    return this;
  }

  /**
   * Erase stack items.
   * @param {Number} start
   * @param {Number} end
   * @returns {Buffer[]}
   */

  erase(start, end) {
    if (start < 0)
      start = this.items.length + start;

    if (end < 0)
      end = this.items.length + end;

    this.items.splice(start, end - start);
  }

  /**
   * Swap stack values.
   * @param {Number} i1 - Index 1.
   * @param {Number} i2 - Index 2.
   */

  swap(i1, i2) {
    if (i1 < 0)
      i1 = this.items.length + i1;

    if (i2 < 0)
      i2 = this.items.length + i2;

    const v1 = this.items[i1];
    const v2 = this.items[i2];

    this.items[i1] = v2;
    this.items[i2] = v1;
  }

  /*
   * Data
   */

  getData(index) {
    return this.get(index);
  }

  popData() {
    return this.pop();
  }

  shiftData() {
    return this.shift();
  }

  removeData(index) {
    return this.remove(index);
  }

  setData(index, data) {
    return this.set(index, data);
  }

  pushData(data) {
    return this.push(data);
  }

  unshiftData(data) {
    return this.unshift(data);
  }

  insertData(index, data) {
    return this.insert(index, data);
  }

  /*
   * Length
   */

  getLength(index) {
    const item = this.get(index);
    return item ? item.length : -1;
  }

  /*
   * String
   */

  getString(index, enc) {
    const item = this.get(index);
    return item ? Stack.toString(item, enc) : null;
  }

  popString(enc) {
    const item = this.pop();
    return item ? Stack.toString(item, enc) : null;
  }

  shiftString(enc) {
    const item = this.shift();
    return item ? Stack.toString(item, enc) : null;
  }

  removeString(index, enc) {
    const item = this.remove(index);
    return item ? Stack.toString(item, enc) : null;
  }

  setString(index, str, enc) {
    return this.set(index, Stack.fromString(str, enc));
  }

  pushString(str, enc) {
    return this.push(Stack.fromString(str, enc));
  }

  unshiftString(str, enc) {
    return this.unshift(Stack.fromString(str, enc));
  }

  insertString(index, str, enc) {
    return this.insert(index, Stack.fromString(str, enc));
  }

  /*
   * Num
   */

  getNum(index, minimal, limit) {
    const item = this.get(index);
    return item ? Stack.toNum(item, minimal, limit) : null;
  }

  popNum(minimal, limit) {
    const item = this.pop();
    return item ? Stack.toNum(item, minimal, limit) : null;
  }

  shiftNum(minimal, limit) {
    const item = this.shift();
    return item ? Stack.toNum(item, minimal, limit) : null;
  }

  removeNum(index, minimal, limit) {
    const item = this.remove(index);
    return item ? Stack.toNum(item, minimal, limit) : null;
  }

  setNum(index, num) {
    return this.set(index, Stack.fromNum(num));
  }

  pushNum(num) {
    return this.push(Stack.fromNum(num));
  }

  unshiftNum(num) {
    return this.unshift(Stack.fromNum(num));
  }

  insertNum(index, num) {
    return this.insert(index, Stack.fromNum(num));
  }

  /*
   * Int
   */

  getInt(index, minimal, limit) {
    const item = this.get(index);
    return item ? Stack.toInt(item, minimal, limit) : -1;
  }

  popInt(minimal, limit) {
    const item = this.pop();
    return item ? Stack.toInt(item, minimal, limit) : -1;
  }

  shiftInt(minimal, limit) {
    const item = this.shift();
    return item ? Stack.toInt(item, minimal, limit) : -1;
  }

  removeInt(index, minimal, limit) {
    const item = this.remove(index);
    return item ? Stack.toInt(item, minimal, limit) : -1;
  }

  setInt(index, num) {
    return this.set(index, Stack.fromInt(num));
  }

  pushInt(num) {
    return this.push(Stack.fromInt(num));
  }

  unshiftInt(num) {
    return this.unshift(Stack.fromInt(num));
  }

  insertInt(index, num) {
    return this.insert(index, Stack.fromInt(num));
  }

  /*
   * Bool
   */

  getBool(index) {
    const item = this.get(index);
    return item ? Stack.toBool(item) : false;
  }

  popBool() {
    const item = this.pop();
    return item ? Stack.toBool(item) : false;
  }

  shiftBool() {
    const item = this.shift();
    return item ? Stack.toBool(item) : false;
  }

  removeBool(index) {
    const item = this.remove(index);
    return item ? Stack.toBool(item) : false;
  }

  setBool(index, value) {
    return this.set(index, Stack.fromBool(value));
  }

  pushBool(value) {
    return this.push(Stack.fromBool(value));
  }

  unshiftBool(value) {
    return this.unshift(Stack.fromBool(value));
  }

  insertBool(index, value) {
    return this.insert(index, Stack.fromBool(value));
  }

  /**
   * Test an object to see if it is a Stack.
   * @param {Object} obj
   * @returns {Boolean}
   */

  static isStack(obj) {
    return obj instanceof Stack;
  }

  /*
   * Encoding
   */

  static toString(item, enc) {
    assert(Buffer.isBuffer(item));
    return item.toString(enc || 'utf8');
  }

  static fromString(str, enc) {
    assert(typeof str === 'string');
    return Buffer.from(str, enc || 'utf8');
  }

  static toNum(item, minimal, limit) {
    return ScriptNum.decode(item, minimal, limit);
  }

  static fromNum(num) {
    assert(ScriptNum.isScriptNum(num));
    return num.encode();
  }

  static toInt(item, minimal, limit) {
    const num = Stack.toNum(item, minimal, limit);
    return num.getInt();
  }

  static fromInt(int) {
    assert(typeof int === 'number');

    if (int >= -1 && int <= 16)
      return common.small[int + 1];

    const num = ScriptNum.fromNumber(int);

    return Stack.fromNum(num);
  }

  static toBool(item) {
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
  }

  static fromBool(value) {
    assert(typeof value === 'boolean');
    return Stack.fromInt(value ? 1 : 0);
  }
}

/*
 * Expose
 */

module.exports = Stack;
