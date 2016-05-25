/*!
 * bst.js - iterative binary search tree for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

var utils = require('./utils');
var assert = utils.assert;
var DUMMY = new Buffer([0]);

/**
 * An iterative in-memory binary search tree. Used for the mempool.
 * Many of its options, parameters and methods mimic the leveldown interface.
 * @exports BST
 * @constructor
 * @param {String?} location - Phony location.
 * @param {Object?} options
 * @param {Function} options.compare - Comparator.
 */

function BST(location, options) {
  if (!(this instanceof BST))
    return new BST(location, options);

  if (!options)
    options = {};

  this.options = options;
  this.root = null;
  this.compare = options.compare || utils.cmp;
}

/**
 * Do a key lookup.
 * @param {String|Buffer} key
 * @returns {Buffer?} value
 */

BST.prototype.search = function search(key) {
  var current = this.root;
  var cmp;

  if (typeof key === 'string')
    key = new Buffer(key, 'ascii');

  while (current) {
    cmp = this.compare(key, current.key);
    if (cmp === 0)
      return current.value;
    if (cmp < 0)
      current = current.left;
    else
      current = current.right;
  }
};

/**
 * Insert a record.
 * @param {String|Buffer} key
 * @param {Buffer} value
 */

BST.prototype.insert = function insert(key, value) {
  var current = this.root;
  var left = false;
  var parent, cmp;

  if (typeof key === 'string')
    key = new Buffer(key, 'ascii');

  if (typeof value === 'string')
    value = new Buffer(value, 'utf8');

  while (current) {
    cmp = this.compare(key, current.key);

    if (cmp === 0) {
      current.value = value;
      return;
    }

    if (cmp < 0) {
      parent = current;
      left = true;
      current = current.left;
    } else {
      parent = current;
      left = false;
      current = current.right;
    }
  }

  if (!parent) {
    this.root = { key: key, value: value };
    return;
  }

  if (left)
    parent.left = { key: key, value: value };
  else
    parent.right = { key: key, value: value };
};

/**
 * Remove a record.
 * @param {Buffer|String} key
 * @returns {Boolean}
 */

BST.prototype.remove = function remove(key) {
  var current = this.root;
  var left = false;
  var cmp, parent, use;

  if (typeof key === 'string')
    key = new Buffer(key, 'ascii');

  while (current) {
    cmp = this.compare(key, current.key);

    if (cmp === 0)
      break;

    if (cmp < 0) {
      parent = current;
      left = true;
      current = current.left;
    } else {
      parent = current;
      left = false;
      current = current.right;
    }
  }

  if (!current)
    return false;

  if (!current.left && !current.right) {
    if (!parent) {
      this.root = null;
    } else {
      if (left)
        parent.left = null;
      else
        parent.right = null;
    }

    return true;
  }

  if (!current.left || !current.right) {
    if (current.left)
      current = current.left;
    else
      current = current.right;

    if (!parent) {
      this.root = current;
    } else {
      if (left)
        parent.left = current;
      else
        parent.right = current;
    }

    return true;
  }

  parent = current;
  use = current.left;
  left = true;
  while (use.right) {
    parent = use;
    use = use.right;
    left = false;
  }

  current.key = use.key;
  current.value = use.value;

  if (left)
    current.left = use.left;
  else
    parent.right = use.left;

  return true;
};

/**
 * Take a snapshot and return a cloned root node.
 * @return {Object}
 */

BST.prototype.snapshot = function snapshot() {
  var current = this.root;
  var stack = [];
  var left = true;
  var parent, copy, snapshot;

  for (;;) {
    if (current) {
      if (left) {
        copy = clone(current);
        if (parent)
          parent.left = copy;
        else
          snapshot = copy;
      } else {
        copy = clone(current);
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

  return snapshot;
};

/**
 * Traverse the key and filter records.
 * @param {Function} test
 * @returns {Object[]} Matched records.
 */

BST.prototype.traverse = function traverse(test) {
  var current = this.root;
  var stack = [];
  var items = [];

  for (;;) {
    if (current) {
      if (test(current)) {
        items.push({
          key: current.key,
          value: current.value
        });
      }
      stack.push(current);
      current = current.left;
      continue;
    }

    if (stack.length === 0)
      break;

    current = stack.pop();
    current = current.right;
  }

  return items;
};

/**
 * Dump all records.
 * @returns {Object[]} Records.
 */

BST.prototype.dump = function dump() {
  return this.traverse(function() { return true; });
};

/**
 * Traverse between a range of keys and collect records.
 * @param {Buffer} gte
 * @param {Buffer} lte
 * @returns {Object[]} records
 */

BST.prototype.range = function range(gte, lte) {
  var current = this.root;
  var stack = [];
  var items = [];
  var cmp;

  if (typeof gte === 'string')
    gte = new Buffer(gte, 'ascii');

  if (typeof lte === 'string')
    lte = new Buffer(lte, 'ascii');

  for (;;) {
    if (current) {
      cmp = this.rangeCompare(current.key, gte, lte);
      if (cmp === 0) {
        items.push({
          key: current.key,
          value: current.value
        });
        stack.push(current);
      }
      if (cmp <= 0)
        current = current.left;
      else
        current = current.right;
      continue;
    }

    if (stack.length === 0)
      break;

    current = stack.pop();
    current = current.right;
  }

  return items;
};

/**
 * Comparator for {@link BST#range}.
 * @param {Buffer} key
 * @param {Buffer} gteKey
 * @param {Buffer} lteKey
 * @returns {Number}
 */

BST.prototype.rangeCompare = function rangeCompare(key, gteKey, lteKey) {
  var gte, lte;

  if (gteKey)
    gte = this.compare(key, gteKey);
  else
    gte = 0;

  if (lteKey)
    lte = this.compare(key, lteKey);
  else
    lte = 0;

  if (gte >= 0 && lte <= 0)
    return 0;

  if (lte > 0)
    return -1;

  if (gte < 0)
    return 1;

  assert(false);
};

/**
 * Open the database (leveldown method).
 * @param {Object?} options
 * @param {Function} callback
 */

BST.prototype.open = function open(options, callback) {
  if (!callback) {
    callback = options;
    options = null;
  }

  if (!options)
    options = {};

  this.options = options;

  return utils.nextTick(callback);
};

/**
 * Close the database (leveldown method).
 * @param {Function} callback
 */

BST.prototype.close = function close(callback) {
  return utils.nextTick(callback);
};

/**
 * Retrieve a record (leveldown method).
 * @param {Buffer|String} key
 * @param {Object?} options
 * @param {Function} callback - Returns [Error, Buffer].
 */

BST.prototype.get = function get(key, options, callback) {
  var value, err;

  if (!callback) {
    callback = options;
    options = null;
  }

  if (!options)
    options = {};

  value = this.search(key);

  if (!value) {
    err = new Error('BST_NOTFOUND: Key not found.');
    err.notFound = true;
    err.type = 'NotFoundError';
    return utils.asyncify(callback)(err);
  }

  if (options.asBuffer === false)
    value = value.toString('utf8');

  return utils.asyncify(callback)(null, value);
};

/**
 * Insert a record (leveldown method).
 * @param {Buffer|String} key
 * @param {Buffer} value
 * @param {Object?} options
 * @param {Function} callback
 */

BST.prototype.put = function put(key, value, options, callback) {
  if (!callback) {
    callback = options;
    options = null;
  }

  if (!options)
    options = {};

  this.insert(key, value);

  return utils.nextTick(callback);
};

/**
 * Remove a record (leveldown method).
 * @param {Buffer|String} key
 * @param {Object?} options
 * @param {Function} callback
 */

BST.prototype.del = function del(key, options, callback) {
  if (!callback) {
    callback = options;
    options = null;
  }

  if (!options)
    options = {};

  this.remove(key);

  return utils.nextTick(callback);
};

/**
 * Create an atomic batch (leveldown method).
 * @see Leveldown.Batch
 * @param {Object[]?} ops
 * @param {Object?} options
 * @param {Function} callback
 * @returns {Leveldown.Batch}
 */

BST.prototype.batch = function batch(ops, options, callback) {
  var batch;

  if (!callback) {
    callback = options;
    options = null;
  }

  if (!options)
    options = {};

  batch = new Batch(this, options);

  if (ops) {
    batch.ops = ops.slice();
    return batch.write(callback);
  }

  return batch;
};

/**
 * Create an iterator (leveldown method).
 * @param {Object} options - See {Leveldown.Iterator}.
 * @returns {Leveldown.Iterator}.
 */

BST.prototype.iterator = function iterator(options) {
  return new Iterator(this, options);
};

/**
 * Get a database property (leveldown method) (NOP).
 * @param {String} name - Property name.
 * @returns {String}
 */

BST.prototype.getProperty = function getProperty(name) {
  return '';
};

/**
 * Calculate approximate database size (leveldown method).
 * @param {String} start - Start key.
 * @param {String} end - End key.
 * @param {Function} callback - Returns [Error, Number].
 */

BST.prototype.approximateSize = function approximateSize(start, end, callback) {
  var size = this.range(start, end).reduce(function(total, item) {
    return total + item.key.length + item.value.length;
  }, 0);
  return utils.asyncify(callback)(null, size);
};

/**
 * Destroy the database (leveldown function) (NOP).
 * @param {String} location
 * @param {Function} callback
 */

BST.destroy = function destroy(location, callback) {
  return utils.nextTick(callback);
};

/**
 * Repair the database (leveldown function) (NOP).
 * @param {String} location
 * @param {Function} callback
 */

BST.repair = function repair(location, callback) {
  return utils.nextTick(callback);
};

/*
 * Batch
 */

function Batch(tree, options) {
  this.options = options || {};
  this.ops = [];
  this.tree = tree;
}

Batch.prototype.put = function(key, value) {
  assert(this.tree, 'Already written.');
  this.ops.push({ type: 'put', key: key, value: value });
  return this;
};

Batch.prototype.del = function del(key) {
  assert(this.tree, 'Already written.');
  this.ops.push({ type: 'del', key: key });
  return this;
};

Batch.prototype.write = function write(callback) {
  var self = this;

  if (!this.tree)
    return utils.asyncify(callback)(new Error('Already written.'));

  this.ops.forEach(function(op) {
    if (op.type === 'put')
      self.tree.insert(op.key, op.value);
    else if (op.type === 'del')
      self.tree.remove(op.key);
    else
      assert(false);
  });

  this.ops.length = 0;
  delete this.ops;
  delete this.options;
  delete this.tree;

  utils.nextTick(callback);

  return this;
};

Batch.prototype.clear = function clear() {
  assert(this.tree, 'Already written.');
  this.ops.length = 0;
  return this;
};

/*
 * Iterator
 */

function Iterator(tree, options) {
  if (!options)
    options = {};

  assert(!options.lt, 'LT is not implemented.');
  assert(!options.gt, 'GT is not implemented.');

  this.options = {
    keys: options.keys,
    values: options.values,
    gte: options.gte || options.start,
    lte: options.lte || options.end,
    keyAsBuffer: options.keyAsBuffer,
    valueAsBuffer: options.valueAsBuffer,
    reverse: options.reverse,
    limit: options.limit
  };

  this.tree = tree;
  this.ended = false;
  this.items = this.tree.range(this.options.gte, this.options.lte);
  this.index = this.options.reverse ? this.items.length - 1 : 0;
  this.total = 0;
}

Iterator.prototype.next = function(callback) {
  var item, key, value;

  if (this.ended)
    return utils.asyncify(callback)(new Error('Cannot call next after end.'));

  if (this.options.reverse)
    item = this.items[this.index--];
  else
    item = this.items[this.index++];

  if (this.options.limit != null) {
    if (this.total++ >= this.options.limit) {
      this._end();
      return utils.nextTick(callback);
    }
  }

  if (!item) {
    this._end();
    return utils.nextTick(callback);
  }

  key = item.key;
  value = item.value;

  if (this.options.keys === false)
    key = DUMMY;

  if (this.options.values === false)
    value = DUMMY;

  if (this.options.keyAsBuffer === false)
    key = key.toString('ascii');

  if (this.options.valueAsBuffer === false)
    value = value.toString('utf8');

  utils.asyncify(callback)(null, key, value);
};

Iterator.prototype.seek = function seek(key) {
  var self = this;
  var item;

  assert(!this.ended, 'Already ended.');

  if (typeof key === 'string')
    key = new Buffer(key, 'ascii');

  this.index = utils.binarySearch(this.items, key, function(a, b) {
    return self.tree.compare(a.key, b);
  }, true);

  item = this.items[this.index];

  if (!item || this.tree.compare(item.key, key) !== 0)
    this.index += 1;
};

Iterator.prototype._end = function end() {
  if (!this.tree)
    return;

  delete this.tree;
  this.items.length = 0;
  delete this.items;
};

Iterator.prototype.end = function end(callback) {
  if (this.ended)
    return utils.asyncify(callback)(new Error('Already ended.'));

  this.ended = true;
  this._end();

  return utils.nextTick(callback);
};

/*
 * Helpers
 */

function clone(node) {
  return {
    key: node.key,
    value: node.value,
    left: node.left,
    right: node.right
  };
}

/*
 * Expose
 */

module.exports = BST;
