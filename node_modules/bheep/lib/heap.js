/*!
 * heap.js - heap object for bcoin
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');

/**
 * Binary Heap
 * @alias module:utils.Heap
 */

class Heap {
  /**
   * Create a binary heap.
   * @constructor
   * @param {Function?} compare
   */

  constructor(compare) {
    this.compare = comparator;
    this.items = [];

    if (compare)
      this.set(compare);
  }

  /**
   * Initialize and sort heap.
   */

  init() {
    const n = this.items.length;

    if (n <= 1)
      return;

    for (let i = (n / 2 | 0) - 1; i >= 0; i--)
      this.down(i, n);
  }

  /**
   * Get heap size.
   * @returns {Number}
   */

  size() {
    return this.items.length;
  }

  /**
   * Set comparator.
   * @param {Function} compare
   */

  set(compare) {
    assert(typeof compare === 'function',
      'Comparator must be a function.');
    this.compare = compare;
  }

  /**
   * Push item onto heap.
   * @param {Object} item
   * @returns {Number}
   */

  insert(item) {
    this.items.push(item);
    this.up(this.items.length - 1);
    return this.items.length;
  }

  /**
   * Pop next item off of heap.
   * @param {Object} item
   * @returns {Object}
   */

  shift() {
    if (this.items.length === 0)
      return null;

    const n = this.items.length - 1;

    this.swap(0, n);
    this.down(0, n);

    return this.items.pop();
  }

  /**
   * Remove item from heap.
   * @param {Number} i
   * @returns {Object}
   */

  remove(i) {
    if (this.items.length === 0)
      return null;

    const n = this.items.length - 1;

    if (i < 0 || i > n)
      return null;

    if (n !== i) {
      this.swap(i, n);
      this.down(i, n);
      this.up(i);
    }

    return this.items.pop();
  }

  /**
   * Swap indicies.
   * @private
   * @param {Number} a
   * @param {Number} b
   */

  swap(a, b) {
    const x = this.items[a];
    const y = this.items[b];
    this.items[a] = y;
    this.items[b] = x;
  }

  /**
   * Compare indicies.
   * @private
   * @param {Number} i
   * @param {Number} j
   * @returns {Boolean}
   */

  less(i, j) {
    return this.compare(this.items[i], this.items[j]) < 0;
  }

  /**
   * Bubble item down.
   * @private
   * @param {Number} i
   * @param {Number} n
   */

  down(i, n) {
    for (;;) {
      const l = 2 * i + 1;

      assert(l >= 0);

      if (l < 0 || l >= n)
        break;

      let j = l;
      const r = l + 1;

      if (r < n && !this.less(l, r))
        j = r;

      if (!this.less(j, i))
        break;

      this.swap(i, j);
      i = j;
    }
  }

  /**
   * Bubble item up.
   * @private
   * @param {Number} i
   */

  up(i) {
    for (;;) {
      const j = (i - 1) / 2 | 0;

      assert(j >= 0);

      if (j < 0 || j === i)
        break;

      if (!this.less(i, j))
        break;

      this.swap(j, i);
      i = j;
    }
  }

  /**
   * Convert heap to sorted array.
   * @returns {Object[]}
   */

  toArray() {
    const heap = new Heap();
    const result = [];

    heap.compare = this.compare;
    heap.items = this.items.slice();

    while (heap.size() > 0)
      result.push(heap.shift());

    return result;
  }

  /**
   * Instantiate heap from array and comparator.
   * @param {Function} compare
   * @param {Object[]} items
   * @returns {Heap}
   */

  static fromArray(compare, items) {
    const heap = new Heap();
    heap.set(compare);
    heap.items = items;
    heap.init();
    return heap;
  }
}

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
