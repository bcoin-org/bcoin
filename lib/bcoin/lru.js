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

LRU.prototype._getSize = function _getSize(item) {
  var keySize = item.key.length * 2;

  if (item.value == null)
    return keySize + 1;

  if (typeof item.value === 'number')
    return keySize + 4;

  if (item.value._raw)
    return keySize + item.value._raw.length;

  if (item.value.getSize)
    return keySize + item.value.getSize();

  if (typeof item.value._size === 'number')
    return keySize + item.value._size;

  if (typeof item.value === 'string')
    return keySize + item.value.length * 2;

  if (typeof item.value.length === 'number')
    return keySize + item.value.length;

  return keySize + 1;
};

LRU.prototype._compact = function _compact() {
  var item;

  if (this.size <= this.maxSize)
    return;

  for (item = this.head; item; item = item.next) {
    if (this.size < this.maxSize)
      break;
    this.remove(item.key);
  }
};

LRU.prototype.set = function set(key, value) {
  var item = this.data[key];

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
  var item = this.data[key];

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
  var item = this.data[key];

  if (!item)
    return false;

  this.size -= this._getSize(item);

  delete this.data[key];

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

  if (item == this.tail)
    this.tail = item.prev || this.head;

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
var a6 = '6';
var lru = new LRU(((2 * 4) + 4) * 2);
lru.set('a1', a1);
assert(lru.get('a1') === '1');
assert(lru.size === ((2 * 1) + 1) * 2);
assert(lru.head.key === 'a1' && lru.tail.key === 'a1' && !lru.head.prev && !lru.head.next);
lru._keys();
// console.log(lru._keys());
lru.set('a2', a2);
assert(lru.get('a2') === '2');
assert(lru.size === ((2 * 2) + 2) * 2);
assert(lru.head.key === 'a1' && lru.tail.key === 'a2'
  && !lru.head.prev && lru.head.next.key === 'a2'
  && !lru.tail.next && lru.tail.prev.key === 'a1');
lru._keys();
// console.log(lru._keys());
lru.set('a3', a3);
assert(lru.get('a3') === '3');
assert(lru.size === ((2 * 3) + 3) * 2);
lru._keys();
// console.log(lru._keys());
lru.set('a3', a3);
assert(lru.get('a3') === '3');
assert(lru.size === ((2 * 3) + 3) * 2);
lru._keys();
// console.log(lru._keys());
lru.set('a4', a4);
assert(lru.get('a4') === '4');
assert(lru.size === ((2 * 4) + 4) * 2);
lru._keys();
// console.log(lru._keys());
assert(lru.get('a1'));
lru.remove('a1');
lru._keys();
// console.log(lru._keys());
var _a3 = lru.head.next;
assert(_a3.key === 'a3');
assert(_a3.prev === lru.head && _a3.next === lru.tail);
assert(lru.head.key === 'a2' && lru.tail.key === 'a4'
  && !lru.head.prev && lru.head.next.key === 'a3'
  && !lru.tail.next && lru.tail.prev.key === 'a3');
lru.set('a5', a5);
assert(lru.get('a5') === '5');
assert(lru.size === ((2 * 4) + 4) * 2);
assert(!lru.get('a1'));
lru._keys();
// console.log(lru._keys());
lru.get('a2');
lru._keys();
// console.log(lru._keys());
lru.set('a6', a6);
assert(lru.get('a6') === '6');
assert(lru.size === ((2 * 4) + 4) * 2);
assert(!lru.get('a3'));
lru._keys();
// console.log(lru._keys());

/**
 * Expose
 */

module.exports = LRU;
