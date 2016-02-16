/**
 * lru.js - LRU cache for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bcoin = require('../bcoin');
var utils = bcoin.utils;
var assert = utils.assert;

/**
 * LRU
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

  if (this.size <= this.maxSize)
    return;

  for (item = this.head; item; item = item.next) {
    // if (this.size <= this.maxSize / 2 | 0)
    if (this.size < this.maxSize)
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
    this._remove(item);
    this._append(item);
    this._compact();
    return;
  }

  item = { key: key, value: value };

  this.data[key] = item;

  this._append(item);

  this.size += this._getSize(value);

  this._compact();
};

LRU.prototype.get = function get(key) {
  var item = this.data[key];
  var prev, next, tail;

  if (!item)
    return;

  this._remove(item);
  this._append(item);

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

  this._remove(item);

  return true;
};

LRU.prototype._prepend = function prepend(item) {
  this._insert(null, item);
};

LRU.prototype._append = function prepend(item) {
  this._insert(this.tail, item);
};

LRU.prototype._insert = function insert(ref, item) {
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

LRU.prototype._remove = function insert(item) {
  if (item.prev)
    item.prev.next = item.next;

  if (item.next)
    item.next.prev = item.prev;

  if (this.head === item)
    this.head = item.next;

  if (this.tail === item)
    this.tail = item.prev;

  item.prev = null;
  item.next = null;
};

LRU.prototype._keys = function _keys() {
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

var a1 = '1';
var a2 = '2';
var a3 = '3';
var a4 = '4';
var a5 = '5';
var lru = new LRU(5);
lru.set('a1', a1);
assert(lru.get('a1') === '1');
assert(lru.size === 1);
assert(lru.head.key === 'a1' && lru.tail.key === 'a1' && !lru.head.prev && !lru.head.next);
console.log(lru._keys());
lru.set('a2', a2);
assert(lru.get('a2') === '2');
assert(lru.size === 2);
assert(lru.head.key === 'a1' && lru.tail.key === 'a2'
  && !lru.head.prev && lru.head.next.key === 'a2'
  && !lru.tail.next && lru.tail.prev.key === 'a1');
console.log(lru._keys());
lru.set('a3', a3);
assert(lru.get('a3') === '3');
assert(lru.size === 3);
console.log(lru._keys());
lru.set('a3', a3);
assert(lru.get('a3') === '3');
assert(lru.size === 3);
console.log(lru._keys());
lru.set('a4', a4);
assert(lru.get('a4') === '4');
assert(lru.size === 4);
console.log(lru._keys());
// lru.set('a5', a5);
// assert(lru.get('a5') === '5');
// assert(lru.size === 4);
// assert(!lru.get('a1'));
assert(lru.get('a1'));
lru.remove('a1');
console.log(lru._keys());
var _a3 = lru.head.next;
assert(_a3.key === 'a3');
assert(_a3.prev === lru.head && _a3.next === lru.tail);
assert(lru.head.key === 'a2' && lru.tail.key === 'a4'
  && !lru.head.prev && lru.head.next.key === 'a3'
  && !lru.tail.next && lru.tail.prev.key === 'a3');

/**
 * Expose
 */

module.exports = LRU;
