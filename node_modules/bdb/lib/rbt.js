/*!
 * rbt.js - red black tree for bcoin
 * Copyright (c) 2016-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');

/*
 * Constants
 */

const RED = 0;
const BLACK = 1;

let SENTINEL = null;

/**
 * Red-black Tree
 */

class RBT {
  /**
   * Create a red black tree.
   * @constructor
   * @param {Function} compare - Comparator.
   * @param {Boolean?} unique
   */

  constructor(compare, unique) {
    assert(typeof compare === 'function');

    this.root = SENTINEL;
    this.compare = compare;
    this.unique = unique || false;
  }

  /**
   * Clear the tree.
   */

  reset() {
    this.root = SENTINEL;
  }

  /**
   * Do a key lookup.
   * @param {Buffer|String} key
   * @returns {Buffer?} value
   */

  search(key) {
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
  }

  /**
   * Insert a record.
   * @param {Buffer|String} key
   * @param {Buffer} value
   */

  insert(key, value) {
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

    const node = new RBTNode(key, value);

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
  }

  /**
   * Repaint necessary nodes after insertion.
   * @private
   * @param {RBTNode} x
   */

  insertFixup(x) {
    x.color = RED;

    while (x !== this.root && x.parent.color === RED) {
      if (x.parent === x.parent.parent.left) {
        const y = x.parent.parent.right;
        if (!y.isNull() && y.color === RED) {
          x.parent.color = BLACK;
          y.color = BLACK;
          x.parent.parent.color = RED;
          x = x.parent.parent;
        } else {
          if (x === x.parent.right) {
            x = x.parent;
            this.rotl(x);
          }
          x.parent.color = BLACK;
          x.parent.parent.color = RED;
          this.rotr(x.parent.parent);
        }
      } else {
        const y = x.parent.parent.left;
        if (!y.isNull() && y.color === RED) {
          x.parent.color = BLACK;
          y.color = BLACK;
          x.parent.parent.color = RED;
          x = x.parent.parent;
        } else {
          if (x === x.parent.left) {
            x = x.parent;
            this.rotr(x);
          }
          x.parent.color = BLACK;
          x.parent.parent.color = RED;
          this.rotl(x.parent.parent);
        }
      }
    }

    this.root.color = BLACK;
  }

  /**
   * Remove a record.
   * @param {Buffer|String} key
   * @returns {Boolean}
   */

  remove(key) {
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
  }

  /**
   * Remove a single node.
   * @private
   * @param {RBTNode} z
   */

  removeNode(z) {
    let y = z;

    if (!z.left.isNull() && !z.right.isNull())
      y = this.successor(z);

    const x = y.left.isNull() ? y.right : y.left;
    x.parent = y.parent;

    if (y.parent.isNull()) {
      this.root = x;
    } else {
      if (y === y.parent.left)
        y.parent.left = x;
      else
        y.parent.right = x;
    }

    if (y !== z) {
      z.key = y.key;
      z.value = y.value;
    }

    if (y.color === BLACK)
      this.removeFixup(x);
  }

  /**
   * Repaint necessary nodes after removal.
   * @private
   * @param {RBTNode} x
   */

  removeFixup(x) {
    while (x !== this.root && x.color === BLACK) {
      if (x === x.parent.left) {
        let w = x.parent.right;

        if (w.color === RED) {
          w.color = BLACK;
          x.parent.color = RED;
          this.rotl(x.parent);
          w = x.parent.right;
        }

        if (w.left.color === BLACK && w.right.color === BLACK) {
          w.color = RED;
          x = x.parent;
        } else {
          if (w.right.color === BLACK) {
            w.left.color = BLACK;
            w.color = RED;
            this.rotr(w);
            w = x.parent.right;
          }
          w.color = x.parent.color;
          x.parent.color = BLACK;
          w.right.color = BLACK;
          this.rotl(x.parent);
          x = this.root;
        }
      } else {
        let w = x.parent.left;

        if (w.color === RED) {
          w.color = BLACK;
          x.parent.color = RED;
          this.rotr(x.parent);
          w = x.parent.left;
        }

        if (w.right.color === BLACK && w.left.color === BLACK) {
          w.color = RED;
          x = x.parent;
        } else {
          if (w.left.color === BLACK) {
            w.right.color = BLACK;
            w.color = RED;
            this.rotl(w);
            w = x.parent.left;
          }
          w.color = x.parent.color;
          x.parent.color = BLACK;
          w.left.color = BLACK;
          this.rotr(x.parent);
          x = this.root;
        }
      }
    }

    x.color = BLACK;
  }

  /**
   * Do a left rotate.
   * @private
   * @param {RBTNode} x
   */

  rotl(x) {
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
  }

  /**
   * Do a right rotate.
   * @private
   * @param {RBTNode} x
   */

  rotr(x) {
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
  }

  /**
   * Minimum subtree.
   * @private
   * @param {RBTNode} z
   * @returns {RBTNode}
   */

  min(z) {
    if (z.isNull())
      return z;

    while (!z.left.isNull())
      z = z.left;

    return z;
  }

  /**
   * Maximum subtree.
   * @private
   * @param {RBTNode} z
   * @returns {RBTNode}
   */

  max(z) {
    if (z.isNull())
      return z;

    while (!z.right.isNull())
      z = z.right;

    return z;
  }

  /**
   * Successor node.
   * @private
   * @param {RBTNode} x
   * @returns {RBTNode}
   */

  successor(x) {
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
  }

  /**
   * Predecessor node.
   * @private
   * @param {RBTNode} x
   * @returns {RBTNode}
   */

  predecessor(x) {
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
  }

  /**
   * Take a snapshot and return
   * a cloned root node (iterative).
   * @returns {RBTNode}
   */

  clone() {
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
  }

  /**
   * Take a snapshot and return
   * a cloned root node (recursive).
   * @returns {RBTNode}
   */

  snapshot() {
    if (this.root.isNull())
      return SENTINEL;

    const node = this.root.clone();

    copyLeft(node, node.left);
    copyRight(node, node.right);

    return node;
  }

  /**
   * Create an iterator.
   * @param {RBTNode?} snapshot
   * @returns {RBTIterator}
   */

  iterator(snapshot) {
    return new RBTIterator(this, snapshot || this.root);
  }

  /**
   * Traverse between a range of keys and collect records.
   * @param {Buffer} min
   * @param {Buffer} max
   * @returns {RBTNode[]} Records.
   */

  range(min, max) {
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
  }
}

/**
 * RBT Iterator
 */

class RBTIterator {
  /**
   * Create an iterator.
   * @constructor
   * @param {RBT} tree
   * @param {RBTNode} snapshot
   * @property {RBT} tree
   * @property {RBTNode} current
   * @property {Object} key
   * @property {Object} value
   */

  constructor(tree, snapshot) {
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

  compare(key) {
    assert(this.key != null, 'No key.');
    return this.tree.compare(this.key, key);
  }

  /**
   * Test whether current node is valid.
   */

  valid() {
    return !this.current.isNull();
  }

  /**
   * Seek to the root.
   */

  reset() {
    this.current = this.root;
    this.key = null;
    this.value = null;
  }

  /**
   * Seek to the start of the tree.
   */

  seekFirst() {
    this.current = this.tree.min(this.root);
    this.key = this.current.key;
    this.value = this.current.value;
  }

  /**
   * Seek to the end of the tree.
   */

  seekLast() {
    this.current = this.tree.max(this.root);
    this.key = this.current.key;
    this.value = this.current.value;
  }

  /**
   * Seek to a key from the current node (gte).
   * @param {String} key
   */

  seek(key) {
    return this.seekMin(key);
  }

  /**
   * Seek to a key from the current node (gte).
   * @param {String} key
   */

  seekMin(key) {
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
  }

  /**
   * Seek to a key from the current node (lte).
   * @param {String} key
   */

  seekMax(key) {
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
  }

  /**
   * Seek to previous node.
   * @param {String} key
   */

  prev() {
    if (this.current.isNull()) {
      this.key = null;
      this.value = null;
      return false;
    }

    this.key = this.current.key;
    this.value = this.current.value;
    this.current = this.tree.predecessor(this.current);

    return true;
  }

  /**
   * Seek to next node.
   * @returns {Boolean}
   */

  next() {
    if (this.current.isNull()) {
      this.key = null;
      this.value = null;
      return false;
    }

    this.key = this.current.key;
    this.value = this.current.value;
    this.current = this.tree.successor(this.current);

    return true;
  }

  /**
   * Return the current key/value pair.
   * @returns {RBTData}
   */

  data() {
    assert(this.key != null, 'No data available.');
    return new RBTData(this.key, this.value);
  }
}

/**
 * RBT Node
 */

class RBTNode {
  /**
   * Create an RBT node.
   * @constructor
   * @param {Buffer} key
   * @param {Buffer} value
   * @property {Buffer} key
   * @property {Buffer} value
   * @property {Number} color
   * @property {RBTNode|RBTSentinel} parent
   * @property {RBTNode|RBTSentinel} left
   * @property {RBTNode|RBTSentinel} right
   */

  constructor(key, value) {
    this.key = key;
    this.value = value;
    this.color = RED;
    this.parent = SENTINEL;
    this.left = SENTINEL;
    this.right = SENTINEL;
  }

  /**
   * Clone the node.
   * @returns {RBTNode}
   */

  clone() {
    const node = new RBTNode(this.key, this.value);
    node.color = this.color;
    node.parent = this.parent;
    node.left = this.left;
    node.right = this.right;
    return node;
  }

  /**
   * Clone the node (key/value only).
   * @returns {RBTData}
   */

  copy() {
    return new RBTData(this.key, this.value);
  }

  /**
   * Inspect the rbt node.
   * @returns {Object}
   */

  inspect() {
    return {
      key: this.key,
      value: this.value,
      color: this.color === RED ? 'red' : 'black',
      left: this.left,
      right: this.right
    };
  }

  /**
   * Test whether the node is a leaf.
   * Always returns false.
   * @returns {Boolean}
   */

  isNull() {
    return false;
  }
}

/**
 * RBT Sentinel
 */

class RBTSentinel {
  /**
   * Create an RBT Sentinel Node.
   * @constructor
   * @property {null} key
   * @property {null} value
   * @property {Number} [color=BLACK]
   * @property {null} parent
   * @property {null} left
   * @property {null} right
   */

  constructor() {
    this.key = null;
    this.value = null;
    this.color = BLACK;
    this.parent = null;
    this.left = null;
    this.right = null;
  }

  /**
   * Inspect the rbt node.
   * @returns {String}
   */

  inspect() {
    return 'NIL';
  }

  /**
   * Test whether the node is a leaf.
   * Always returns true.
   * @returns {Boolean}
   */

  isNull() {
    return true;
  }
}

/**
 * RBT Data
 */

class RBTData {
  /**
   * Create an RBT key/value pair.
   * @constructor
   * @param {Buffer} key
   * @param {Buffer} value
   * @property {Buffer} key
   * @property {Buffer} value
   */

  constructor(key, value) {
    this.key = key;
    this.value = value;
  }
}

/*
 * Helpers
 */

SENTINEL = new RBTSentinel();

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

module.exports = RBT;
