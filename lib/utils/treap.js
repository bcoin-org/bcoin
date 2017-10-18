/*!
 * treap.js - iterative treap for bcoin
 * A treap uses a random priority assigned to nodes at insertion
 * and uses it to maintain a (min)-heap property in addition
 * to the binary search tree property.
 *
 * As a result, the expected time for search, insert and delete are
 * all O(log n).
 *
 * After regular binary search tree insertion, we balance the tree
 * to maintain (min)-heap property for the new node
 * (which has a random priority).
 *
 * Before deletion, we do the opposite, i.e. move the node to be deleted
 * to a leaf by balancing as necessary.
 *
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const random = require('../crypto/random');
const assert = require('assert');
let SENTINEL;

/**
 * An iterative treap.
 * @alias module:utils.Treap
 * @constructor
 * @param {Function} compare - Comparator.
 * @param {Boolean?} unique
 */

function Treap(compare, unique) {
  if (!(this instanceof Treap))
    return new Treap(compare, unique);

  assert(typeof compare === 'function');

  this.root = SENTINEL;
  this.compare = compare;
  this.unique = unique || false;
}

/**
 * Clear the tree.
 */

Treap.prototype.reset = function reset() {
  this.root = SENTINEL;
};

/**
 * Do a key lookup.
 * @param {Buffer|String} key
 * @returns {Buffer?} value
 */

Treap.prototype.search = function search(key) {
  let current = this.root;

  while (!current.isNull()) {
    const cmp = this.compare(key, current.key);

    if (cmp === 0)
      return current;

    if (cmp < 0)
      current = current.left;
    else
      current = current.right;
  }

  return null;
};

/**
 * Insert a record.
 * @param {Buffer|String} key
 * @param {Buffer} value
 */

Treap.prototype.insert = function insert(key, value) {
  let current = this.root;
  let left = false;
  let parent;

  while (!current.isNull()) {
    const cmp = this.compare(key, current.key);

    if (this.unique && cmp === 0) {
      current.key = key;
      current.value = value;
      return current;
    }

    parent = current;

    if (cmp < 0) {
      left = true;
      current = current.left;
    } else {
      left = false;
      current = current.right;
    }
  }

  const node = new TreapNode(key, value, random.randomInt());

  if (!parent) {
    this.root = node;
    this.insertFixup(node);
    return node;
  }

  node.parent = parent;

  if (left)
    parent.left = node;
  else
    parent.right = node;

  this.insertFixup(node);

  return node;
};

/**
 * Balance as necessary to maintain (min)-heap property.
 * @private
 * @param {TreapNode} x
 */

Treap.prototype.insertFixup = function insertFixup(x) {
  // As long as the node has a priority smaller than it's parent
  // we need to balance it as necessary.
  while (x !== this.root && x.priority < x.parent.priority) {
    // Rotate left if the node is on the right and vice-versa.
    if (x === x.parent.right) {
      this.rotl(x.parent);
    } else {
      this.rotr(x.parent);
    }
  }
};

/**
 * Remove a record.
 * @param {Buffer|String} key
 * @returns {Boolean}
 */

Treap.prototype.remove = function remove(key) {
  let current = this.root;

  while (!current.isNull()) {
    const cmp = this.compare(key, current.key);

    if (cmp === 0) {
      this.removeNode(current);
      return current;
    }

    if (cmp < 0)
      current = current.left;
    else
      current = current.right;
  }

  return null;
};

/**
 * Remove a single node.
 * @private
 * @param {TreapNode} z
 */

Treap.prototype.removeNode = function removeNode(z) {
  // Move the node to a leaf before deleting it.
  this.removeFixup(z);

  if (z !== this.root) {
    // Delete the node.
    if (z === z.parent.left)
      z.parent.left = SENTINEL;
    else
      z.parent.right = SENTINEL;
    return;
  }

  this.root = SENTINEL;
};

/**
 * Balance as necessary to move given node to leaf.
 * This must be done **before** calling removeNode.
 * @private
 * @param {TreapNode} x
 */

Treap.prototype.removeFixup = function removeFixup(x) {
  while (!(x.left === SENTINEL && x.right === SENTINEL)) {
    if (x.left.priority < x.right.priority) {
      this.rotr(x);
    } else {
      this.rotl(x);
    }
  }
};

/**
 * Do a left rotate.
 * @private
 * @param {TreapNode} x
 */

Treap.prototype.rotl = function rotl(x) {
  const y = x.right;

  x.right = y.left;

  if (!y.left.isNull())
    y.left.parent = x;

  y.parent = x.parent;

  if (x.parent.isNull()) {
    this.root = y;
  } else {
    if (x === x.parent.left)
      x.parent.left = y;
    else
      x.parent.right = y;
  }

  y.left = x;
  x.parent = y;
};

/**
 * Do a right rotate.
 * @private
 * @param {TreapNode} x
 */

Treap.prototype.rotr = function rotr(x) {
  const y = x.left;

  x.left = y.right;

  if (!y.right.isNull())
    y.right.parent = x;

  y.parent = x.parent;

  if (x.parent.isNull()) {
    this.root = y;
  } else {
    if (x === x.parent.right)
      x.parent.right = y;
    else
      x.parent.left = y;
  }

  y.right = x;
  x.parent = y;
};

/**
 * Minimum subtree.
 * @private
 * @param {TreapNode} z
 * @returns {TreapNode}
 */

Treap.prototype.min = function min(z) {
  if (z.isNull())
    return z;

  while (!z.left.isNull())
    z = z.left;

  return z;
};

/**
 * Maximum subtree.
 * @private
 * @param {TreapNode} z
 * @returns {TreapNode}
 */

Treap.prototype.max = function max(z) {
  if (z.isNull())
    return z;

  while (!z.right.isNull())
    z = z.right;

  return z;
};

/**
 * Successor node.
 * @private
 * @param {TreapNode} x
 * @returns {TreapNode}
 */

Treap.prototype.successor = function successor(x) {
  if (!x.right.isNull()) {
    x = x.right;

    while (!x.left.isNull())
      x = x.left;

    return x;
  }

  let y = x.parent;
  while (!y.isNull() && x === y.right) {
    x = y;
    y = y.parent;
  }

  return y;
};

/**
 * Predecessor node.
 * @private
 * @param {TreapNode} x
 * @returns {TreapNode}
 */

Treap.prototype.predecessor = function predecessor(x) {
  if (!x.left.isNull()) {
    x = x.left;

    while (!x.right.isNull())
      x = x.right;

    return x;
  }

  let y = x.parent;
  while (!y.isNull() && x === y.left) {
    x = y;
    y = y.parent;
  }

  return y;
};

/**
 * Take a snapshot and return
 * a cloned root node (iterative).
 * @returns {TreapNode}
 */

Treap.prototype.clone = function clone() {
  if (this.root.isNull())
    return SENTINEL;

  const stack = [];

  let current = this.root;
  let left = true;
  let parent, snapshot;

  for (;;) {
    if (!current.isNull()) {
      const copy = current.clone();

      if (parent)
        copy.parent = parent;

      if (left) {
        if (parent)
          parent.left = copy;
        else
          snapshot = copy;
      } else {
        if (parent)
          parent.right = copy;
        else
          snapshot = copy;
      }

      stack.push(copy);
      parent = copy;
      left = true;
      current = current.left;
      continue;
    }

    if (stack.length === 0)
      break;

    current = stack.pop();
    parent = current;
    left = false;
    current = current.right;
  }

  assert(snapshot);

  return snapshot;
};

/**
 * Take a snapshot and return
 * a cloned root node (recursive).
 * @returns {TreapNode}
 */

Treap.prototype.snapshot = function snapshot() {
  if (this.root.isNull())
    return SENTINEL;

  const node = this.root.clone();

  copyLeft(node, node.left);
  copyRight(node, node.right);

  return node;
};

/**
 * Create an iterator.
 * @param {TreapNode?} snapshot
 * @returns {Iterator}
 */

Treap.prototype.iterator = function iterator(snapshot) {
  return new Iterator(this, snapshot || this.root);
};

/**
 * Traverse between a range of keys and collect records.
 * @param {Buffer} min
 * @param {Buffer} max
 * @returns {TreapNode[]} Records.
 */

Treap.prototype.range = function range(min, max) {
  const iter = this.iterator();
  const items = [];

  if (min)
    iter.seekMin(min);
  else
    iter.seekFirst();

  while (iter.next()) {
    if (max && iter.compare(max) > 0)
      break;

    items.push(iter.data());
  }

  return items;
};

/**
 * Iterator
 * @constructor
 * @ignore
 * @param {Treap} tree
 * @param {TreapNode} snapshot
 * @property {Treap} tree
 * @property {TreapNode} current
 * @property {Object} key
 * @property {Object} value
 */

function Iterator(tree, snapshot) {
  this.tree = tree;
  this.root = snapshot;
  this.current = snapshot;
  this.key = null;
  this.value = null;
}

/**
 * Compare keys using tree's comparator.
 * @param {Object} key
 */

Iterator.prototype.compare = function compare(key) {
  assert(this.key != null, 'No key.');
  return this.tree.compare(this.key, key);
};

/**
 * Test whether current node is valid.
 */

Iterator.prototype.valid = function valid() {
  return !this.current.isNull();
};

/**
 * Seek to the root.
 */

Iterator.prototype.reset = function reset() {
  this.current = this.root;
  this.key = null;
  this.value = null;
};

/**
 * Seek to the start of the tree.
 */

Iterator.prototype.seekFirst = function seekFirst() {
  this.current = this.tree.min(this.root);
  this.key = this.current.key;
  this.value = this.current.value;
};

/**
 * Seek to the end of the tree.
 */

Iterator.prototype.seekLast = function seekLast() {
  this.current = this.tree.max(this.root);
  this.key = this.current.key;
  this.value = this.current.value;
};

/**
 * Seek to a key from the current node (gte).
 * @param {String} key
 */

Iterator.prototype.seek = function seek(key) {
  return this.seekMin(key);
};

/**
 * Seek to a key from the current node (gte).
 * @param {String} key
 */

Iterator.prototype.seekMin = function seekMin(key) {
  assert(key != null, 'No key passed to seek.');

  let root = this.current;
  let current = SENTINEL;

  while (!root.isNull()) {
    const cmp = this.tree.compare(root.key, key);

    if (cmp === 0) {
      current = root;
      break;
    }

    if (cmp > 0) {
      current = root;
      root = root.left;
    } else {
      root = root.right;
    }
  }

  this.current = current;
  this.key = current.key;
  this.value = current.value;
};

/**
 * Seek to a key from the current node (lte).
 * @param {String} key
 */

Iterator.prototype.seekMax = function seekMax(key) {
  assert(key != null, 'No key passed to seek.');

  let root = this.current;
  let current = SENTINEL;

  while (!root.isNull()) {
    const cmp = this.tree.compare(root.key, key);

    if (cmp === 0) {
      current = root;
      break;
    }

    if (cmp < 0) {
      current = root;
      root = root.right;
    } else {
      root = root.left;
    }
  }

  this.current = current;
  this.key = current.key;
  this.value = current.value;
};

/**
 * Seek to previous node.
 * @param {String} key
 */

Iterator.prototype.prev = function prev() {
  if (this.current.isNull()) {
    this.key = null;
    this.value = null;
    return false;
  }

  this.key = this.current.key;
  this.value = this.current.value;
  this.current = this.tree.predecessor(this.current);

  return true;
};

/**
 * Seek to next node.
 * @returns {Boolean}
 */

Iterator.prototype.next = function next() {
  if (this.current.isNull()) {
    this.key = null;
    this.value = null;
    return false;
  }

  this.key = this.current.key;
  this.value = this.current.value;
  this.current = this.tree.successor(this.current);

  return true;
};

/**
 * Return the current key/value pair.
 * @returns {TreapData}
 */

Iterator.prototype.data = function data() {
  assert(this.key != null, 'No data available.');
  return new TreapData(this.key, this.value);
};

/**
 * Treap Node
 * @constructor
 * @ignore
 * @private
 * @param {Buffer} key
 * @param {Buffer} value
 * @property {Buffer} key
 * @property {Buffer} value
 * @property {Number} priority
 * @property {TreapNode|TreapSentinel} parent
 * @property {TreapNode|TreapSentinel} left
 * @property {TreapNode|TreapSentinel} right
 */

function TreapNode(key, value, priority) {
  this.key = key;
  this.value = value;
  this.priority = priority;
  this.parent = SENTINEL;
  this.left = SENTINEL;
  this.right = SENTINEL;
}

/**
 * Clone the node.
 * @returns {TreapNode}
 */

TreapNode.prototype.clone = function clone() {
  return new TreapNode(this.key, this.value, this.priority);
};

/**
 * Clone the node (key/value only).
 * @returns {TreapData}
 */

TreapNode.prototype.copy = function copy() {
  return new TreapData(this.key, this.value);
};

/**
 * Inspect the treap node.
 * @returns {Object}
 */

TreapNode.prototype.inspect = function inspect() {
  return {
    key: this.key,
    value: this.value,
    priority: this.priority,
    left: this.left,
    right: this.right
  };
};

/**
 * Test whether the node is a leaf.
 * Always returns false.
 * @returns {Boolean}
 */

TreapNode.prototype.isNull = function isNull() {
  return false;
};

/**
 * Treap Sentinel Node
 * @constructor
 * @ignore
 * @property {null} key
 * @property {null} value
 * @property {Number} priority
 * @property {null} parent
 * @property {null} left
 * @property {null} right
 */

function TreapSentinel() {
  this.key = null;
  this.value = null;
  this.priority = Infinity;
  this.parent = null;
  this.left = null;
  this.right = null;
}

/**
 * Inspect the treap node.
 * @returns {String}
 */

TreapSentinel.prototype.inspect = function inspect() {
  return 'NIL';
};

/**
 * Test whether the node is a leaf.
 * Always returns true.
 * @returns {Boolean}
 */

TreapSentinel.prototype.isNull = function isNull() {
  return true;
};

/**
 * Treap key/value pair
 * @constructor
 * @ignore
 * @param {Buffer} key
 * @param {Buffer} value
 * @property {Buffer} key
 * @property {Buffer} value
 */

function TreapData(key, value) {
  this.key = key;
  this.value = value;
}

/**
 * Inspect the treap data.
 * @returns {Object}
 */

TreapData.prototype.inspect = function inspect() {
  return {
    key: this.key,
    value: this.value
  };
};

/*
 * Helpers
 */

SENTINEL = new TreapSentinel();

function copyLeft(parent, node) {
  if (!node.isNull()) {
    parent.left = node.clone();
    parent.left.parent = parent;
    copyLeft(parent.left, node.left);
    copyRight(parent.left, node.right);
  }
}

function copyRight(parent, node) {
  if (!node.isNull()) {
    parent.right = node.clone();
    parent.right.parent = parent;
    copyLeft(parent.right, node.left);
    copyRight(parent.right, node.right);
  }
}

/*
 * Expose
 */

module.exports = Treap;
