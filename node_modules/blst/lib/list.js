/*!
 * list.js - double linked list for bcoin
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');

/**
 * Double Linked List
 * @alias module:utils.List
 */

class List {
  /**
   * Create a list.
   * @constructor
   * @property {ListItem|null} head
   * @property {ListItem|null} tail
   * @property {Number} size
   */

  constructor() {
    this.head = null;
    this.tail = null;
    this.size = 0;
  }

  /**
   * Reset the cache. Clear all items.
   */

  reset() {
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
  }

  /**
   * Remove the first item in the list.
   * @returns {ListItem}
   */

  shift() {
    const item = this.head;

    if (!item)
      return null;

    this.remove(item);

    return item;
  }

  /**
   * Prepend an item to the linked list (sets new head).
   * @param {ListItem}
   * @returns {Boolean}
   */

  unshift(item) {
    return this.insert(null, item);
  }

  /**
   * Append an item to the linked list (sets new tail).
   * @param {ListItem}
   * @returns {Boolean}
   */

  push(item) {
    return this.insert(this.tail, item);
  }

  /**
   * Remove the last item in the list.
   * @returns {ListItem}
   */

  pop() {
    const item = this.tail;

    if (!item)
      return null;

    this.remove(item);

    return item;
  }

  /**
   * Insert item into the linked list.
   * @private
   * @param {ListItem|null} ref
   * @param {ListItem} item
   * @returns {Boolean}
   */

  insert(ref, item) {
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
      this.size += 1;
      return true;
    }

    item.next = ref.next;
    item.prev = ref;
    ref.next = item;

    if (item.next)
      item.next.prev = item;

    if (ref === this.tail)
      this.tail = item;

    this.size += 1;

    return true;
  }

  /**
   * Remove item from the linked list.
   * @private
   * @param {ListItem}
   * @returns {Boolean}
   */

  remove(item) {
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

    this.size -= 1;

    return true;
  }

  /**
   * Replace an item in-place.
   * @param {ListItem} ref
   * @param {ListItem} item
   */

  replace(ref, item) {
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
  }

  /**
   * Slice the list to an array of items.
   * Will remove the items sliced.
   * @param {Number?} total
   * @returns {ListItem[]}
   */

  slice(total) {
    if (total == null)
      total = -1;

    const items = [];

    let next = null;

    for (let item = this.head; item; item = next) {
      next = item.next;
      item.prev = null;
      item.next = null;

      this.size -= 1;

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
  }

  /**
   * Convert the list to an array of items.
   * @returns {ListItem[]}
   */

  toArray() {
    const items = [];

    for (let item = this.head; item; item = item.next)
      items.push(item);

    return items;
  }
}

/**
 * List Item
 * @alias module:utils.ListItem
 */

class ListItem {
  /**
   * Create a list item.
   * @constructor
   * @private
   * @param {String} key
   * @param {Object} value
   */

  constructor(value) {
    this.next = null;
    this.prev = null;
    this.value = value;
  }
}

/*
 * Expose
 */

exports = List;
exports.List = List;
exports.ListItem = ListItem;
exports.Item = ListItem;

module.exports = exports;
