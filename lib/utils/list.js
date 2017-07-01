/*!
 * list.js - double linked list for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');

/**
 * A double linked list.
 * @alias module:utils.List
 * @constructor
 * @property {ListItem|null} head
 * @property {ListItem|null} tail
 * @property {Number} size
 */

function List() {
  if (!(this instanceof List))
    return new List();

  this.head = null;
  this.tail = null;
  this.size = 0;
}

/**
 * Reset the cache. Clear all items.
 */

List.prototype.reset = function reset() {
  let item, next;

  for (item = this.head; item; item = next) {
    next = item.next;
    item.prev = null;
    item.next = null;
  }

  assert(!item);

  this.head = null;
  this.tail = null;
  this.size = 0;
};

/**
 * Remove the first item in the list.
 * @returns {ListItem}
 */

List.prototype.shift = function shift() {
  let item = this.head;

  if (!item)
    return;

  this.remove(item);

  return item;
};

/**
 * Prepend an item to the linked list (sets new head).
 * @param {ListItem}
 * @returns {Boolean}
 */

List.prototype.unshift = function unshift(item) {
  return this.insert(null, item);
};

/**
 * Append an item to the linked list (sets new tail).
 * @param {ListItem}
 * @returns {Boolean}
 */

List.prototype.push = function push(item) {
  return this.insert(this.tail, item);
};

/**
 * Remove the last item in the list.
 * @returns {ListItem}
 */

List.prototype.pop = function pop() {
  let item = this.tail;

  if (!item)
    return;

  this.remove(item);

  return item;
};

/**
 * Insert item into the linked list.
 * @private
 * @param {ListItem|null} ref
 * @param {ListItem} item
 * @returns {Boolean}
 */

List.prototype.insert = function insert(ref, item) {
  if (item.prev || item.next || item === this.head)
    return false;

  assert(!item.prev);
  assert(!item.next);

  if (ref == null) {
    if (!this.head) {
      this.head = item;
      this.tail = item;
    } else {
      this.head.prev = item;
      item.next = this.head;
      this.head = item;
    }
    this.size++;
    return true;
  }

  item.next = ref.next;
  item.prev = ref;
  ref.next = item;

  if (ref === this.tail)
    this.tail = item;

  this.size++;

  return true;
};

/**
 * Remove item from the linked list.
 * @private
 * @param {ListItem}
 * @returns {Boolean}
 */

List.prototype.remove = function remove(item) {
  if (!item.prev && !item.next && item !== this.head)
    return false;

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

  this.size--;

  return true;
};

/**
 * Replace an item in-place.
 * @param {ListItem} ref
 * @param {ListItem} item
 */

List.prototype.replace = function replace(ref, item) {
  if (ref.prev)
    ref.prev.next = item;

  if (ref.next)
    ref.next.prev = item;

  item.prev = ref.prev;
  item.next = ref.next;

  ref.next = null;
  ref.prev = null;

  if (this.head === ref)
    this.head = item;

  if (this.tail === ref)
    this.tail = item;
};

/**
 * Slice the list to an array of items.
 * Will remove the items sliced.
 * @param {Number?} total
 * @returns {ListItem[]}
 */

List.prototype.slice = function slice(total) {
  let items = [];
  let item, next;

  if (total == null)
    total = -1;

  for (item = this.head; item; item = next) {
    next = item.next;
    item.prev = null;
    item.next = null;

    this.size--;

    items.push(item);

    if (items.length === total)
      break;
  }

  if (next) {
    this.head = next;
    next.prev = null;
  } else {
    this.head = null;
    this.tail = null;
  }

  return items;
};

/**
 * Convert the list to an array of items.
 * @returns {ListItem[]}
 */

List.prototype.toArray = function toArray() {
  let items = [];

  for (let item = this.head; item; item = item.next)
    items.push(item);

  return items;
};

/**
 * Represents an linked list item.
 * @alias module:utils.ListItem
 * @constructor
 * @private
 * @param {String} key
 * @param {Object} value
 */

function ListItem(value) {
  this.next = null;
  this.prev = null;
  this.value = value;
}

/*
 * Expose
 */

exports = List;
exports.List = List;
exports.ListItem = ListItem;
exports.Item = ListItem;

module.exports = exports;
