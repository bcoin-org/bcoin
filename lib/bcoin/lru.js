/**
 * lru.js - LRU cache for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var utils = require('./utils');
var assert = utils.assert;

/**
 * LRU
 */

function LRU(maxSize, getSize, onRemove) {
  if (!(this instanceof LRU))
    return new LRU(maxSize, getSize);

  this.data = {};
  this.size = 0;
  this.maxSize = maxSize;
  this.getSize = this._createGetSize(getSize);
  this.onRemove = onRemove;

  this.head = null;
  this.tail = null;
}

LRU.prototype._createGetSize = function _createGetSize(size) {
  if (!size)
    return;

  if (typeof size === 'number')
    return function() { return size; };

  if (typeof size === 'function')
    return size;

  assert(false, 'Bad getSize callback.');
};

LRU.prototype._getSize = function _getSize(item) {
  var keySize = item.key.length * 2;

  if (this.getSize)
    return this.getSize(item.key, item.value);

  if (item.value == null)
    return keySize + 1;

  if (typeof item.value === 'number')
    return keySize + 4;

  if (typeof item.value === 'string')
    return keySize + item.value.length * 2;

  if (typeof item.value.length === 'number')
    return keySize + item.value.length;

  return 1;
};

LRU.prototype._compact = function _compact() {
  var item, next;

  if (this.size <= this.maxSize)
    return;

  for (item = this.head; item; item = next) {
    if (this.size <= this.maxSize)
      break;
    this.size -= this._getSize(item);
    delete this.data[item.key];
    if (this.onRemove)
      this.onRemove(item.key, item.value);
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

LRU.prototype.reset = function reset() {
  var item, next;

  for (item = this.head; item; item = next) {
    delete this.data[item.key];
    if (this.onRemove)
      this.onRemove(item.key, item.value);
    next = item.next;
    item.prev = null;
    item.next = null;
  }

  assert(!item);

  this.size = 0;
  this.head = null;
  this.tail = null;
};

LRU.prototype.set = function set(key, value) {
  var item;

  key = key + '';

  item = this.data[key];

  if (item) {
    this.size -= this._getSize(item);
    item.value = value;
    this.size += this._getSize(item);
    this._removeList(item);
    this._appendList(item);
    this._compact();
    return;
  }

  item = { key: key, value: value };

  this.data[key] = item;

  this._appendList(item);

  this.size += this._getSize(item);

  this._compact();
};

LRU.prototype.get = function get(key) {
  var item;

  key = key + '';

  item = this.data[key];

  if (!item)
    return;

  this._removeList(item);
  this._appendList(item);

  return item.value;
};

LRU.prototype.has = function get(key) {
  return this.data[key] != null;
};

LRU.prototype.remove = function remove(key) {
  var item;

  key = key + '';

  item = this.data[key];

  if (!item)
    return false;

  this.size -= this._getSize(item);

  delete this.data[key];
  if (this.onRemove)
    this.onRemove(item.key, item.value);

  this._removeList(item);

  return true;
};

LRU.prototype._prependList = function prependList(item) {
  this._insertList(null, item);
};

LRU.prototype._appendList = function appendList(item) {
  this._insertList(this.tail, item);
};

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

LRU.prototype.items = function items() {
  var items = [];
  var item;

  for (item = this.head; item; item = item.next)
    items.push(item);

  return items;
};

LRU.prototype.iterator = function iterator() {
  return {
    item: { next: this.head },
    next: function() {
      this.item = this.item.next;
      return this.item;
    }
  };
};

/**
 * Expose
 */

module.exports = LRU;
