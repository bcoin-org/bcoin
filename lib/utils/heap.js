/*!
 * heap.js - heap object for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');

/**
 * Binary Heap
 * @alias module:utils.Heap
 * @constructor
 * @param {Function?} compare
 */

function Heap(compare) {
  if (!(this instanceof Heap))
    return new Heap(compare);

  this.compare = comparator;
  this.items = [];

  if (compare)
    this.set(compare);
}

/**
 * Initialize and sort heap.
 */

Heap.prototype.init = function init() {
  let n = this.items.length;
  let i;

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
 * @param {Function} compare
 */

Heap.prototype.set = function set(compare) {
  assert(typeof compare === 'function',
    'Comparator must be a function.');
  this.compare = compare;
};

/**
 * Push item onto heap.
 * @param {Object} item
 * @returns {Number}
 */

Heap.prototype.insert = function insert(item) {
  this.items.push(item);
  this.up(this.items.length - 1);
  return this.items.length;
};

/**
 * Pop next item off of heap.
 * @param {Object} item
 * @returns {Object}
 */

Heap.prototype.shift = function shift() {
  let n;

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
  let n;

  if (this.items.length === 0)
    return;

  n = this.items.length - 1;

  if (i < 0 || i > n)
    return;

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
  let x = this.items[a];
  let y = this.items[b];
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
  return this.compare(this.items[i], this.items[j]) < 0;
};

/**
 * Bubble item down.
 * @private
 * @param {Number} i
 * @param {Number} n
 */

Heap.prototype.down = function down(i, n) {
  let j, l, r;

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
  let j;

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
  let heap = new Heap();
  let result = [];

  heap.compare = this.compare;
  heap.items = this.items.slice();

  while (heap.size() > 0)
    result.push(heap.shift());

  return result;
};

/**
 * Instantiate heap from array and comparator.
 * @param {Function} compare
 * @param {Object[]} items
 * @returns {Heap}
 */

Heap.fromArray = function fromArray(compare, items) {
  let heap = new Heap();
  heap.set(compare);
  heap.items = items;
  heap.init();
  return heap;
};

/*
 * Helpers
 */

function comparator(a, b) {
  throw new Error('No heap comparator set.');
}

/*
 * Expose
 */

module.exports = Heap;
