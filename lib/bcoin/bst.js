/**
 * bst.js - iterative binary search tree for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bcoin = require('../bcoin');
var utils = require('./utils');
var assert = utils.assert;
var DUMMY = new Buffer([0]);

/**
 * BST
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

BST.prototype.remove = function remove(key) {
  var current = this.root;
  var left = false;
  var parent, use;

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

BST.prototype.dump = function dump() {
  return this.traverse(function() { return true; });
};

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
 * Leveldown Methods
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

BST.prototype.close = function close(callback) {
  return utils.nextTick(callback);
};

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

BST.prototype.put = function put(key, value, options, callback) {
  var item;

  if (!callback) {
    callback = options;
    options = null;
  }

  if (!options)
    options = {};

  this.insert(key, value);

  return utils.nextTick(callback);
};

BST.prototype.del = function del(key, options, callback) {
  var item;

  if (!callback) {
    callback = options;
    options = null;
  }

  if (!options)
    options = {};

  this.remove(key);

  return utils.nextTick(callback);
};

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

BST.prototype.iterator = function iterator(options) {
  return new Iterator(this, options);
};

BST.prototype.getProperty = function getProperty(name) {
  return null;
};

BST.prototype.approximateSize = function approximateSize(start, end, callback) {
  var size = this.range(start, end).reduce(function(total, item) {
    return total + item.key.length + item.value.length;
  }, 0);
  return utils.asyncify(callback)(null, size);
};

BST.destroy = function destroy(location, callback) {
  return utils.nextTick(callback);
};

BST.repair = function repair(location, callback) {
  return utils.nextTick(callback);
};

/**
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

/**
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

  assert(!this.ended, 'Already ended.');

  if (typeof key === 'string')
    key = new Buffer(key, 'ascii');

  this.index = binarySearch(this.items, key, true, function(a, b) {
    return self.tree.compare(a.key, b);
  });
};

Iterator.prototype._end = function end(callback) {
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

/**
 * Helpers
 */

function binarySearch(items, key, insert, compare) {
  var start = 0;
  var end = items.length - 1;
  var pos, cmp;

  if (!compare)
    compare = utils.cmp;

  while (start <= end) {
    pos = (start + end) >>> 1;
    cmp = compare(items[pos], key);

    if (cmp === 0)
      return pos;

    if (cmp < 0)
      start = pos + 1;
    else
      end = pos - 1;
  }

  if (!insert)
    return -1;

  return start - 1;
}

function clone(node) {
  return {
    key: node.key,
    value: node.value,
    left: node.left,
    right: node.right
  };
}

/**
 * Expose
 */

module.exports = BST;

if (module.parent)
  return;

var tree = new BST();

function bench(tree, name) {
  var start = Date.now();
  var istart = Date.now();
  for (var i = 0; i < 100000; i++) {
    tree.insert('foo ' + i, 'bar ' + i);
  }
  console.log('%s insert: %d', name, Date.now() - istart);
  var sstart = Date.now();
  for (var i = 0; i < 100000; i++) {
    tree.search('foo ' + i);
  }
  console.log('%s search: %d', name, Date.now() - sstart);
  var rstart = Date.now();
  for (var i = 0; i < 100000; i++) {
    if (i > 50000)
      tree.remove('foo ' + i);
  }
  console.log('%s remove: %d', name, Date.now() - rstart);
  var itstart = Date.now();
  tree.range('foo 700', 'foo 80000');
  console.log('%s iter: %d', name, Date.now() - itstart);
  console.log('%s total: %d', name, Date.now() - start);
}

bench(tree, 'tree');

var tree = new BST();
for (var i = 0; i < 1000; i++) {
  tree.insert('foo ' + i, 'bar ' + i);
}
for (var i = 0; i < 1000; i++) {
  assert(tree.search('foo ' + i).toString('utf8') === 'bar ' + i);
  if (i > 900)
    tree.remove('foo ' + i);
}
for (var i = 0; i < 1000; i++) {
  if (i > 900)
    assert(tree.search('foo ' + i) == null);
  else
    assert(tree.search('foo ' + i).toString('utf8') === 'bar ' + i);
}

var items = tree.range('foo 700', 'foo 800');

//utils.print(items);

tree.open(function() {
  var batch = tree.batch();
  for (var i = 0; i < 1000; i++) {
    var key = 'foo ' + i;
    var val = new Buffer('bar ' + i, 'ascii');
    batch.put(key, val);
  }
  batch.write(function(err) {
    if (err)
      throw err;
    var batch = tree.batch();
    for (var i = 0; i < 1000; i++) {
      var key = 'foo ' + i;
      var val = new Buffer('bar ' + i, 'ascii');
      if (i > 950)
        batch.del(key);
      else
        batch.put(key, val);
    }
    batch.write(function(err) {
      if (err)
        throw err;
      utils.forRangeSerial(0, 1000, function(i, next) {
        var key = 'foo ' + i;
        var val = new Buffer('bar ' + i, 'ascii');
        tree.get(key, function(err, value) {
          if (i > 950) {
            assert(err);
            assert(err.type === 'NotFoundError');
            return next();
          }
          if (err)
            return next(err);
          assert(utils.isEqual(value, val));
          next();
        });
      }, function(err) {
        if (err)
          throw err;
        var iter = tree.iterator({
          gte: 'foo 900',
          lte: 'foo 999',
          keyAsBuffer: false,
          fillCache: false
        });
        (function next() {
          iter.next(function(err, key, value) {
            if (err) {
              return iter.end(function(e) {
                throw err;
              });
            }
            if (key === undefined) {
              return iter.end(function(e) {
                if (e)
                  throw e;
                utils.print(tree.dump());
                tree.approximateSize(null, null, function(err, size) {
                  utils.print(size);
                  return console.log('done');
                });
              });
            }
            console.log(key + ' : ' + value);
            next();
          });
        })();
      });
    });
  });
});
