/*!
 * lru.js - LRU cache for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');

/**
 * An LRU cache, used for caching {@link ChainEntry}s.
 * @alias module:utils.LRU
 * @constructor
 * @param {Number} capacity
 * @param {Function?} getSize
 */

function LRU(capacity, getSize) {
  if (!(this instanceof LRU))
    return new LRU(capacity, getSize);

  this.map = new Map();
  this.size = 0;
  this.items = 0;
  this.head = null;
  this.tail = null;
  this.pending = null;

  assert(typeof capacity === 'number', 'Capacity must be a number.');
  assert(capacity >= 0, 'Capacity cannot be negative.');
  assert(!getSize || typeof getSize === 'function', 'Bad size callback.');

  this.capacity = capacity;
  this.getSize = getSize;
}

/**
 * Calculate size of an item.
 * @private
 * @param {LRUItem} item
 * @returns {Number} Size.
 */

LRU.prototype._getSize = function _getSize(item) {
  let keySize;

  if (this.getSize) {
    keySize = Math.floor(item.key.length * 1.375);
    return 120 + keySize + this.getSize(item.value);
  }

  return 1;
};

/**
 * Compact the LRU linked list.
 * @private
 */

LRU.prototype._compact = function _compact() {
  let item, next;

  if (this.size <= this.capacity)
    return;

  for (item = this.head; item; item = next) {
    if (this.size <= this.capacity)
      break;
    this.size -= this._getSize(item);
    this.items--;
    this.map.delete(item.key);
    next = item.next;
    item.prev = null;
    item.next = null;
  }

  if (!item) {
    this.head = null;
    this.tail = null;
    return;
  }

  this.head = item;
  item.prev = null;
};

/**
 * Reset the cache. Clear all items.
 */

LRU.prototype.reset = function reset() {
  let item, next;

  for (item = this.head; item; item = next) {
    this.map.delete(item.key);
    this.items--;
    next = item.next;
    item.prev = null;
    item.next = null;
  }

  assert(!item);

  this.size = 0;
  this.head = null;
  this.tail = null;
};

/**
 * Add an item to the cache.
 * @param {String|Number} key
 * @param {Object} value
 */

LRU.prototype.set = function set(key, value) {
  let item;

  if (this.capacity === 0)
    return;

  key = key + '';

  item = this.map.get(key);

  if (item) {
    this.size -= this._getSize(item);
    item.value = value;
    this.size += this._getSize(item);
    this._removeList(item);
    this._appendList(item);
    this._compact();
    return;
  }

  item = new LRUItem(key, value);

  this.map.set(key, item);

  this._appendList(item);

  this.size += this._getSize(item);
  this.items++;

  this._compact();
};

/**
 * Retrieve an item from the cache.
 * @param {String|Number} key
 * @returns {Object} Item.
 */

LRU.prototype.get = function get(key) {
  let item;

  if (this.capacity === 0)
    return;

  key = key + '';

  item = this.map.get(key);

  if (!item)
    return;

  this._removeList(item);
  this._appendList(item);

  return item.value;
};

/**
 * Test whether the cache contains a key.
 * @param {String|Number} key
 * @returns {Boolean}
 */

LRU.prototype.has = function get(key) {
  if (this.capacity === 0)
    return false;
  return this.map.has(key + '');
};

/**
 * Remove an item from the cache.
 * @param {String|Number} key
 * @returns {Boolean} Whether an item was removed.
 */

LRU.prototype.remove = function remove(key) {
  let item;

  if (this.capacity === 0)
    return;

  key = key + '';

  item = this.map.get(key);

  if (!item)
    return false;

  this.size -= this._getSize(item);
  this.items--;

  this.map.delete(key);

  this._removeList(item);

  return true;
};

/**
 * Prepend an item to the linked list (sets new head).
 * @private
 * @param {LRUItem}
 */

LRU.prototype._prependList = function prependList(item) {
  this._insertList(null, item);
};

/**
 * Append an item to the linked list (sets new tail).
 * @private
 * @param {LRUItem}
 */

LRU.prototype._appendList = function appendList(item) {
  this._insertList(this.tail, item);
};

/**
 * Insert item into the linked list.
 * @private
 * @param {LRUItem|null} ref
 * @param {LRUItem} item
 */

LRU.prototype._insertList = function insertList(ref, item) {
  assert(!item.next);
  assert(!item.prev);

  if (ref == null) {
    if (!this.head) {
      this.head = item;
      this.tail = item;
    } else {
      this.head.prev = item;
      item.next = this.head;
      this.head = item;
    }
    return;
  }

  item.next = ref.next;
  item.prev = ref;
  ref.next = item;

  if (ref === this.tail)
    this.tail = item;
};

/**
 * Remove item from the linked list.
 * @private
 * @param {LRUItem}
 */

LRU.prototype._removeList = function removeList(item) {
  if (item.prev)
    item.prev.next = item.next;

  if (item.next)
    item.next.prev = item.prev;

  if (item === this.head)
    this.head = item.next;

  if (item === this.tail)
    this.tail = item.prev || this.head;

  if (!this.head)
    assert(!this.tail);

  if (!this.tail)
    assert(!this.head);

  item.prev = null;
  item.next = null;
};

/**
 * Collect all keys in the cache, sorted by LRU.
 * @returns {String[]}
 */

LRU.prototype.keys = function _keys() {
  let keys = [];

  for (let item = this.head; item; item = item.next) {
    if (item === this.head)
      assert(!item.prev);
    if (!item.prev)
      assert(item === this.head);
    if (!item.next)
      assert(item === this.tail);
    keys.push(item.key);
  }

  return keys;
};

/**
 * Collect all values in the cache, sorted by LRU.
 * @returns {String[]}
 */

LRU.prototype.values = function _values() {
  let values = [];

  for (let item = this.head; item; item = item.next)
    values.push(item.value);

  return values;
};

/**
 * Convert the LRU cache to an array of items.
 * @returns {Object[]}
 */

LRU.prototype.toArray = function toArray() {
  let items = [];

  for (let item = this.head; item; item = item.next)
    items.push(item);

  return items;
};

/**
 * Create an atomic batch for the lru
 * (used for caching database writes).
 * @returns {LRUBatch}
 */

LRU.prototype.batch = function batch() {
  return new LRUBatch(this);
};

/**
 * Start the pending batch.
 */

LRU.prototype.start = function start() {
  assert(!this.pending);
  this.pending = this.batch();
};

/**
 * Clear the pending batch.
 */

LRU.prototype.clear = function clear() {
  assert(this.pending);
  this.pending.clear();
};

/**
 * Drop the pending batch.
 */

LRU.prototype.drop = function drop() {
  assert(this.pending);
  this.pending = null;
};

/**
 * Commit the pending batch.
 */

LRU.prototype.commit = function commit() {
  assert(this.pending);
  this.pending.commit();
  this.pending = null;
};

/**
 * Push an item onto the pending batch.
 * @param {String} key
 * @param {Object} value
 */

LRU.prototype.push = function push(key, value) {
  assert(this.pending);

  if (this.capacity === 0)
    return;

  this.pending.set(key, value);
};

/**
 * Push a removal onto the pending batch.
 * @param {String} key
 */

LRU.prototype.unpush = function unpush(key) {
  assert(this.pending);

  if (this.capacity === 0)
    return;

  this.pending.remove(key);
};

/**
 * Represents an LRU item.
 * @alias module:utils.LRUItem
 * @constructor
 * @private
 * @param {String} key
 * @param {Object} value
 */

function LRUItem(key, value) {
  this.key = key;
  this.value = value;
  this.next = null;
  this.prev = null;
}

/**
 * LRU Batch
 * @alias module:utils.LRUBatch
 * @constructor
 * @param {LRU} lru
 */

function LRUBatch(lru) {
  this.lru = lru;
  this.ops = [];
}

/**
 * Push an item onto the batch.
 * @param {String} key
 * @param {Object} value
 */

LRUBatch.prototype.set = function set(key, value) {
  this.ops.push(new LRUOp(false, key, value));
};

/**
 * Push a removal onto the batch.
 * @param {String} key
 */

LRUBatch.prototype.remove = function remove(key) {
  this.ops.push(new LRUOp(true, key, null));
};

/**
 * Clear the batch.
 */

LRUBatch.prototype.clear = function clear() {
  this.ops.length = 0;
};

/**
 * Commit the batch.
 */

LRUBatch.prototype.commit = function commit() {
  for (let op of this.ops) {
    if (op.remove) {
      this.lru.remove(op.key);
      continue;
    }
    this.lru.set(op.key, op.value);
  }

  this.ops.length = 0;
};

/**
 * LRU Op
 * @alias module:utils.LRUOp
 * @constructor
 * @private
 * @param {Boolean} remove
 * @param {String} key
 * @param {Object} value
 */

function LRUOp(remove, key, value) {
  this.remove = remove;
  this.key = key;
  this.value = value;
}

/*
 * Expose
 */

module.exports = LRU;
