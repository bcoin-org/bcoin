/*!
 * heap.js - heap object for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');

/**
 * Priority Queue
 * @alias module:utils.Heap
 * @constructor
 * @param {Function?} cmp
 */

function Heap(cmp) {
  if (!(this instanceof Heap))
    return new Heap(cmp);

  this.cmp = null;
  this.items = [];
  this.set(cmp);
}

/**
 * Initialize and sort heap.
 */

Heap.prototype.init = function init() {
  var n = this.items.length;
  var i;

  if (n <= 1)
    return;

  for (i = (n / 2 | 0) - 1; i >= 0; i--)
    this.down(i, n);
};

/**
 * Get heap size.
 * @returns {Number}
 */

Heap.prototype.size = function size() {
  return this.items.length;
};

/**
 * Set comparator.
 * @param {Function} cmp
 */

Heap.prototype.set = function set(cmp) {
  assert(cmp == null || typeof cmp === 'function',
    'Comparator must be a function.');
  this.cmp = cmp || null;
};

/**
 * Push item onto heap.
 * @param {Object} item
 * @returns {Number}
 */

Heap.prototype.push = function push(item) {
  this.items.push(item);
  this.up(this.items.length - 1);
  return this.items.length;
};

/**
 * Pop next item off of heap.
 * @param {Object} item
 * @returns {Object}
 */

Heap.prototype.pop = function pop(item) {
  var n;

  if (this.items.length === 0)
    return;

  n = this.items.length - 1;

  this.swap(0, n);
  this.down(0, n);

  return this.items.pop();
};

/**
 * Remove item from heap.
 * @param {Number} i
 * @returns {Object}
 */

Heap.prototype.remove = function remove(i) {
  var n;

  if (this.items.length === 0)
    return;

  n = this.items.length - 1;

  if (n !== i) {
    this.swap(i, n);
    this.down(i, n);
    this.up(i);
  }

  return this.items.pop();
};

/**
 * Swap indicies.
 * @private
 * @param {Number} a
 * @param {Number} b
 */

Heap.prototype.swap = function swap(a, b) {
  var x = this.items[a];
  var y = this.items[b];
  this.items[a] = y;
  this.items[b] = x;
};

/**
 * Compare indicies.
 * @private
 * @param {Number} i
 * @param {Number} j
 * @returns {Boolean}
 */

Heap.prototype.less = function less(i, j) {
  return this.cmp(this.items[i], this.items[j]) >= 0;
};

/**
 * Bubble item down.
 * @private
 * @param {Number} i
 * @param {Number} n
 */

Heap.prototype.down = function down(i, n) {
  var j, l, r;

  for (;;) {
    l = 2 * i + 1;

    assert(l >= 0);

    if (l < 0 || l >= n)
      break;

    j = l;
    r = l + 1;

    if (r < n && !this.less(l, r))
      j = r;

    if (!this.less(j, i))
      break;

    this.swap(i, j);
    i = j;
  }
};

/**
 * Bubble item up.
 * @private
 * @param {Number} i
 */

Heap.prototype.up = function up(i) {
  var j;

  for (;;) {
    j = (i - 1) / 2 | 0;

    assert(j >= 0);

    if (j < 0 || j === i)
      break;

    if (!this.less(i, j))
      break;

    this.swap(j, i);
    i = j;
  }
};

/**
 * Convert heap to sorted array.
 * @returns {Object[]}
 */

Heap.prototype.toArray = function toArray() {
  var heap = new Heap(this.cmp);
  var result = [];

  heap.items = this.items.slice();

  while (heap.size() > 0)
    result.push(heap.pop());

  return result.reverse();
};

/**
 * Instantiate heap from array and comparator.
 * @param {Function} cmp
 * @param {Object[]} items
 * @returns {Heap}
 */

Heap.fromArray = function fromArray(cmp, items) {
  var heap = new Heap(cmp);
  heap.items = items;
  heap.init();
  return heap;
};

/*
 * Expose
 */

module.exports = Heap;
