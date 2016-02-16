/**
 * lru.js - LRU cache for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

function LRU(maxSize) {
  if (!(this instanceof LRU))
    return new LRU(maxSize);

  this.data = {};
  this.size = 0;
  this.maxSize = maxSize;
  this.head = null;
  this.tail = null;
}

LRU.prototype._getSize = function _getSize(value) {
  if (value == null)
    return 1;

  if (typeof value === 'number')
    return 4;

  if (value._raw)
    return value._raw.length;

  if (value.getSize)
    return value.getSize();

  if (typeof value.length === 'number')
    return value.length;

  return 1;
};

LRU.prototype._compact = function _compact() {
  var item;

  if (this.size < this.maxSize)
    return;

  for (item = this.head; item; item = item.next) {
    if (this.size <= this.maxSize / 2 | 0)
      break;
    this.size -= this._getSize(item.value);
    delete this.data[item.key];
  }

  if (!item) {
    this.head = null;
    this.tail = null;
    return;
  }

  this.head = item;
  item.prev = null;
};

LRU.prototype.set = function set(key, value) {
  var item = this.data[key];
  if (item) {
    this.size -= this._getSize(item.value);
    this.size += this._getSize(value);
    item.value = value;
    this.get(key);
    this._compact();
    return;
  }

  item = { key: key, value: value };

  this.data[key] = item;

  if (!this.head) {
    this.head = item;
    this.tail = item;
  } else {
    this.tail.next = item;
    item.prev = this.tail;
    this.tail = item;
  }

  this.size += this._getSize(value);

  this._compact();
};

LRU.prototype.get = function get(key) {
  var item = this.data[key];
  var prev, next, tail;

  if (!item)
    return;

  if (this.tail === item)
    return item.value;

  prev = item.prev;
  next = item.next;
  tail = this.tail;

  this.tail = item;

  if (this.head === item)
    this.head = next || item;

  if (prev)
    prev.next = next;

  if (next)
    next.prev = prev;

  item.next = null;
  item.prev = tail;

  return item.value;
};

LRU.prototype.has = function get(key) {
  return this.data[key] != null;
};

LRU.prototype.remove = function remove(key) {
  var item = this.data[key];
  var prev, next;

  if (!item)
    return false;

  this.size -= this._getSize(item.value);

  delete this.data[key];

  prev = item.prev;
  next = item.next;

  if (prev)
    prev.next = next;

  if (next)
    next.prev = prev;

  if (this.tail === item)
    this.tail = prev || null;

  if (this.head === item)
    this.head = next || null;

  return true;
};

/**
 * Expose
 */

module.exports = LRU;
