/*!
 * stack.js - stack object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const common = require('./common');

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

/**
 * Getter to retrieve stack items length.
 * @name module:script.Stack#length_getter
 * @method
 * @private
 * @returns {Number}
 */

Stack.prototype.__defineGetter__('length', function() {
  return this.items.length;
});

/**
 * Setter to set stack items length.
 * @name module:script.Stack#length_setter
 * @method
 * @private
 * @param {Number} value
 * @returns {Number}
 */

Stack.prototype.__defineSetter__('length', function(length) {
  return this.items.length = length;
});

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
  return common.formatStack(this.items);
};

/**
 * Format the stack as bitcoind asm.
 * @param {Boolean?} decode - Attempt to decode hash types.
 * @returns {String} Human-readable script.
 */

Stack.prototype.toASM = function toASM(decode) {
  return common.formatStackASM(this.items, decode);
};

/**
 * Clone the stack.
 * @returns {Stack} Cloned stack.
 */

Stack.prototype.clone = function clone() {
  return new Stack(this.items.slice());
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
 * @returns {Stack}
 */

Stack.prototype.slice = function slice(start, end) {
  this.items = this.items.slice(start, end);
  return this;
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
  if (i < 0)
    i = this.items.length + i;

  if (insert === undefined)
    return this.items.splice(i, remove);

  return this.items.splice(i, remove, insert);
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
 * Insert an item.
 * @param {Number} index
 * @param {Buffer} item
 * @returns {Buffer}
 */

Stack.prototype.insert = function insert(i, item) {
  if (i < 0)
    i = this.items.length + i;

  this.items.splice(i, 0, item);
};

/**
 * Remove an item.
 * @param {Number} index
 * @returns {Buffer}
 */

Stack.prototype.remove = function remove(i) {
  if (i < 0)
    i = this.items.length + i;

  if (i >= this.items.length)
    return;

  return this.items.splice(i, 1)[0];
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
  if (i < 0)
    i = this.items.length + i;

  return this.items[i] = value;
};

/**
 * Swap stack values.
 * @param {Number} i1 - Index 1.
 * @param {Number} i2 - Index 2.
 */

Stack.prototype.swap = function swap(i1, i2) {
  let v1, v2;

  if (i1 < 0)
    i1 = this.items.length + i1;

  if (i2 < 0)
    i2 = this.items.length + i2;

  v1 = this.items[i1];
  v2 = this.items[i2];

  this.items[i1] = v2;
  this.items[i2] = v1;
};

/**
 * Test an object to see if it is a Stack.
 * @param {Object} obj
 * @returns {Boolean}
 */

Stack.isStack = function isStack(obj) {
  return obj && Array.isArray(obj.items) && typeof obj.swap === 'function';
};

/*
 * Expose
 */

module.exports = Stack;
