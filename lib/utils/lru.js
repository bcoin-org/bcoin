/*!
 * lru.js - LRU cache for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');

/**
 * An LRU cache, used for caching {@link ChainEntry}s.
 * @exports LRU
 * @constructor
 * @param {Number} maxSize
 * @param {Function?} getSize
 */

function LRU(maxSize, getSize) {
  if (!(this instanceof LRU))
    return new LRU(maxSize, getSize);

  this.maxSize = maxSize;
  this.getSize = getSize;

  assert(!getSize || typeof getSize === 'function', 'Bad size callback.');

  this.map = {};
  this.size = 0;
  this.head = null;
  this.tail = null;
  this.pending = null;
}

/**
 * Calculate size of an item.
 * @private
 * @param {LRUItem} item
 * @returns {Number} Size.
 */

LRU.prototype._getSize = function _getSize(item) {
  var keySize;

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
  var item, next;

  if (this.size <= this.maxSize)
    return;

  for (item = this.head; item; item = next) {
    if (this.size <= this.maxSize)
      break;
    this.size -= this._getSize(item);
    delete this.map[item.key];
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
  var item, next;

  for (item = this.head; item; item = next) {
    delete this.map[item.key];
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
  var item;

  key = key + '';

  item = this.map[key];

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

  this.map[key] = item;

  this._appendList(item);

  this.size += this._getSize(item);

  this._compact();
};

/**
 * Retrieve an item from the cache.
 * @param {String|Number} key
 * @returns {Object} Item.
 */

LRU.prototype.get = function get(key) {
  var item;

  key = key + '';

  item = this.map[key];

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
  return this.map[key] != null;
};

/**
 * Remove an item from the cache.
 * @param {String|Number} key
 * @returns {Boolean} Whether an item was removed.
 */

LRU.prototype.remove = function remove(key) {
  var item;

  key = key + '';

  item = this.map[key];

  if (!item)
    return false;

  this.size -= this._getSize(item);

  delete this.map[key];

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

LRU.prototype.keys = function keys() {
  var keys = [];
  var item;

  for (item = this.head; item; item = item.next) {
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

LRU.prototype.values = function values() {
  var values = [];
  var item;

  for (item = this.head; item; item = item.next)
    values.push(item.value);

  return values;
};

/**
 * Convert the LRU cache to an array of items.
 * @returns {Object[]}
 */

LRU.prototype.toArray = function toArray() {
  var items = [];
  var item;

  for (item = this.head; item; item = item.next)
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
  this.pending.set(key, value);
};

/**
 * Push a removal onto the pending batch.
 * @param {String} key
 */

LRU.prototype.unpush = function unpush(key) {
  assert(this.pending);
  this.pending.remove(key);
};

/**
 * Represents an LRU item.
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
 * @constructor
 */

function LRUBatch(lru) {
  this.lru = lru;
  this.ops = [];
}

LRUBatch.prototype.set = function set(key, value) {
  this.ops.push(new LRUOp(false, key, value));
};

LRUBatch.prototype.remove = function remove(key) {
  this.ops.push(new LRUOp(true, key));
};

LRUBatch.prototype.clear = function clear() {
  this.ops.length = 0;
};

LRUBatch.prototype.commit = function commit() {
  var i, op;

  for (i = 0; i < this.ops.length; i++) {
    op = this.ops[i];
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
 * @constructor
 */

function LRUOp(remove, key, value) {
  this.remove = remove;
  this.key = key;
  this.value = value;
}

/**
 * A null cache. Every method is a NOP.
 * @constructor
 * @param {Number} size
 */

function NullCache(size) {}

NullCache.prototype.set = function set(key, value) {};
NullCache.prototype.remove = function remove(key) {};
NullCache.prototype.get = function get(key) {};
NullCache.prototype.has = function has(key) { return false; };
NullCache.prototype.reset = function reset() {};
NullCache.prototype.keys = function keys(key) { return []; };
NullCache.prototype.values = function values(key) { return []; };
NullCache.prototype.toArray = function toArray(key) { return []; };
NullCache.prototype.batch = function batch() { return new LRUBatch(this); };
NullCache.prototype.start = function start() {};
NullCache.prototype.clear = function clear() {};
NullCache.prototype.drop = function drop() {};
NullCache.prototype.commit = function commit() {};
NullCache.prototype.push = function push(key, value) {};
NullCache.prototype.unpush = function unpush(key) {};

/*
 * Expose
 */

LRU.Nil = NullCache;

module.exports = LRU;
