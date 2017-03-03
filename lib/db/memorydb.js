/*!
 * memorydb.js - in-memory database for bcoin
 * Copyright (c) 2016-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var util = require('../utils/util');
var RBT = require('../utils/rbt');
var DUMMY = new Buffer([0]);

/**
 * In memory database for bcoin
 * using a red-black tree backend.
 * @alias module:db.MemoryDB
 * @constructor
 * @param {String?} location - Phony location.
 * @param {Object?} options
 * @param {Function} options.compare - Comparator.
 */

function MemoryDB(location, options) {
  if (!(this instanceof MemoryDB))
    return new MemoryDB(location, options);

  if (typeof location !== 'string') {
    options = location;
    location = null;
  }

  if (!options)
    options = {};

  this.location = location;
  this.options = options;
  this.tree = new RBT(util.cmp, true);
}

/**
 * Do a key lookup.
 * @private
 * @param {Buffer|String} key
 * @returns {Buffer?} value
 */

MemoryDB.prototype.search = function search(key) {
  var node;

  if (typeof key === 'string')
    key = new Buffer(key, 'utf8');

  node = this.tree.search(key);

  if (!node)
    return;

  return node.value;
};

/**
 * Insert a record.
 * @private
 * @param {Buffer|String} key
 * @param {Buffer} value
 */

MemoryDB.prototype.insert = function insert(key, value) {
  if (typeof key === 'string')
    key = new Buffer(key, 'utf8');

  if (typeof value === 'string')
    value = new Buffer(value, 'utf8');

  return this.tree.insert(key, value) != null;
};

/**
 * Remove a record.
 * @private
 * @param {Buffer|String} key
 * @returns {Boolean}
 */

MemoryDB.prototype.remove = function remove(key) {
  if (typeof key === 'string')
    key = new Buffer(key, 'utf8');

  return this.tree.remove(key) != null;
};

/**
 * Traverse between a range of keys and collect records.
 * @private
 * @param {Buffer} gte
 * @param {Buffer} lte
 * @returns {RBTNode[]} Records.
 */

MemoryDB.prototype.range = function range(gte, lte) {
  if (typeof gte === 'string')
    gte = new Buffer(gte, 'utf8');

  if (typeof lte === 'string')
    lte = new Buffer(lte, 'utf8');

  return this.tree.range(gte, lte);
};

/**
 * Open the database (leveldown method).
 * @param {Object?} options
 * @param {Function} callback
 */

MemoryDB.prototype.open = function open(options, callback) {
  if (!callback) {
    callback = options;
    options = null;
  }

  if (!options)
    options = {};

  this.options = options;

  util.nextTick(callback);
};

/**
 * Close the database (leveldown method).
 * @param {Function} callback
 */

MemoryDB.prototype.close = function close(callback) {
  util.nextTick(callback);
};

/**
 * Retrieve a record (leveldown method).
 * @param {Buffer|String} key
 * @param {Object?} options
 * @param {Function} callback - Returns Bufer.
 */

MemoryDB.prototype.get = function get(key, options, callback) {
  var value, err;

  if (!callback) {
    callback = options;
    options = null;
  }

  if (!options)
    options = {};

  value = this.search(key);

  if (!value) {
    err = new Error('MemoryDB_NOTFOUND: Key not found.');
    err.notFound = true;
    err.type = 'NotFoundError';
    util.nextTick(function() {
      callback(err);
    });
    return;
  }

  if (options.asBuffer === false)
    value = value.toString('utf8');

  util.nextTick(function() {
    callback(null, value);
  });
};

/**
 * Insert a record (leveldown method).
 * @param {Buffer|String} key
 * @param {Buffer} value
 * @param {Object?} options
 * @param {Function} callback
 */

MemoryDB.prototype.put = function put(key, value, options, callback) {
  if (!callback) {
    callback = options;
    options = null;
  }

  this.insert(key, value);

  util.nextTick(callback);
};

/**
 * Remove a record (leveldown method).
 * @param {Buffer|String} key
 * @param {Object?} options
 * @param {Function} callback
 */

MemoryDB.prototype.del = function del(key, options, callback) {
  if (!callback) {
    callback = options;
    options = null;
  }

  this.remove(key);

  util.nextTick(callback);
};

/**
 * Create an atomic batch (leveldown method).
 * @see Leveldown.Batch
 * @param {Object[]?} ops
 * @param {Object?} options
 * @param {Function} callback
 */

MemoryDB.prototype.batch = function batch(ops, options, callback) {
  var batch;

  if (!callback) {
    callback = options;
    options = null;
  }

  batch = new Batch(this, options);

  if (ops) {
    batch.ops = ops.slice();
    batch.write(callback);
    return;
  }

  return batch;
};

/**
 * Create an iterator (leveldown method).
 * @param {Object} options - See {Leveldown.Iterator}.
 * @returns {Leveldown.Iterator}.
 */

MemoryDB.prototype.iterator = function iterator(options) {
  return new Iterator(this, options);
};

/**
 * Get a database property (leveldown method) (NOP).
 * @param {String} name - Property name.
 * @returns {String}
 */

MemoryDB.prototype.getProperty = function getProperty(name) {
  return '';
};

/**
 * Calculate approximate database size (leveldown method).
 * @param {Buffer|String} start - Start key.
 * @param {Buffer|String} end - End key.
 * @param {Function} callback - Returns Number.
 */

MemoryDB.prototype.approximateSize = function approximateSize(start, end, callback) {
  var items = this.range(start, end);
  var size = 0;
  var i, item;

  for (i = 0; i < items.length; i++) {
    item = items[i];
    size += item.key.length;
    size += item.value.length;
  }

  util.nextTick(function() {
    callback(null, size);
  });
};

/**
 * Destroy the database (leveldown function) (NOP).
 * @param {String} location
 * @param {Function} callback
 */

MemoryDB.destroy = function destroy(location, callback) {
  util.nextTick(callback);
};

/**
 * Repair the database (leveldown function) (NOP).
 * @param {String} location
 * @param {Function} callback
 */

MemoryDB.repair = function repair(location, callback) {
  util.nextTick(callback);
};

/**
 * Batch
 * @constructor
 * @ignore
 * @private
 * @param {RBT} tree
 * @param {Object?} options
 */

function Batch(tree, options) {
  this.options = options || {};
  this.ops = [];
  this.tree = tree;
  this.written = false;
}

/**
 * Insert a record.
 * @param {Buffer|String} key
 * @param {Buffer} value
 */

Batch.prototype.put = function(key, value) {
  assert(!this.written, 'Already written.');
  this.ops.push(new BatchOp('put', key, value));
  return this;
};

/**
 * Remove a record.
 * @param {Buffer|String} key
 */

Batch.prototype.del = function del(key) {
  assert(!this.written, 'Already written.');
  this.ops.push(new BatchOp('del', key));
  return this;
};

/**
 * Commit the batch.
 * @param {Function} callback
 */

Batch.prototype.write = function write(callback) {
  var i, op;

  if (this.written) {
    util.nextTick(function() {
      callback(new Error('Already written.'));
    });
    return;
  }

  for (i = 0; i < this.ops.length; i++) {
    op = this.ops[i];
    switch (op.type) {
      case 'put':
        this.tree.insert(op.key, op.value);
        break;
      case 'del':
        this.tree.remove(op.key);
        break;
      default:
        util.nextTick(function() {
          callback(new Error('Bad operation: ' + op.type));
        });
        return;
    }
  }

  this.ops.length = 0;
  this.written = true;

  util.nextTick(callback);

  return this;
};

/**
 * Clear batch of all ops.
 */

Batch.prototype.clear = function clear() {
  assert(!this.written, 'Already written.');
  this.ops.length = 0;
  return this;
};

/**
 * Batch Operation
 * @constructor
 * @ignore
 * @private
 * @param {String} type
 * @param {Buffer} key
 * @param {Buffer|null} value
 */

function BatchOp(type, key, value) {
  this.type = type;
  this.key = key;
  this.value = value;
}

/**
 * Iterator
 * @constructor
 * @ignore
 * @private
 * @param {RBT} db
 * @param {Object?} options
 */

function Iterator(db, options) {
  this.db = db;
  this.options = new IteratorOptions(options);
  this.iter = null;
  this.ended = false;
  this.total = 0;
  this.init();
}

/**
 * Initialize the iterator.
 */

Iterator.prototype.init = function init() {
  var snapshot = this.db.tree.snapshot();
  var iter = this.db.tree.iterator(snapshot);

  if (this.options.reverse) {
    if (this.options.end) {
      iter.seekMax(this.options.end);
      if (this.options.lt && iter.valid()) {
        if (iter.compare(this.options.end) === 0)
          iter.prev();
      }
    } else {
      iter.seekLast();
    }
  } else {
    if (this.options.start) {
      iter.seekMin(this.options.start);
      if (this.options.gt && iter.valid()) {
        if (iter.compare(this.options.start) === 0)
          iter.next();
      }
    } else {
      iter.seekFirst();
    }
  }

  this.iter = iter;
};

/**
 * Seek to the next key.
 * @param {Function} callback
 */

Iterator.prototype.next = function(callback) {
  var options = this.options;
  var iter = this.iter;
  var key, value, result;

  if (!this.iter) {
    util.nextTick(function() {
      callback(new Error('Cannot call next after end.'));
    });
    return;
  }

  if (options.reverse) {
    result = iter.prev();

    // Stop once we hit a key below our gte key.
    if (result && options.start) {
      if (options.gt) {
        if (iter.compare(options.start) <= 0)
          result = false;
      } else {
        if (iter.compare(options.start) < 0)
          result = false;
      }
    }
  } else {
    result = iter.next();

    // Stop once we hit a key above our lte key.
    if (result && options.end) {
      if (options.lt) {
        if (iter.compare(options.end) >= 0)
          result = false;
      } else {
        if (iter.compare(options.end) > 0)
          result = false;
      }
    }
  }

  if (!result) {
    this.iter = null;
    util.nextTick(callback);
    return;
  }

  if (options.limit !== -1) {
    if (this.total >= options.limit) {
      this.iter = null;
      util.nextTick(callback);
      return;
    }
    this.total += 1;
  }

  key = iter.key;
  value = iter.value;

  if (!options.keys)
    key = DUMMY;

  if (!options.values)
    value = DUMMY;

  if (!options.keyAsBuffer)
    key = key.toString('utf8');

  if (!options.valueAsBuffer)
    value = value.toString('utf8');

  util.nextTick(function() {
    callback(null, key, value);
  });
};

/**
 * Seek to a key gte to `key`.
 * @param {String|Buffer} key
 */

Iterator.prototype.seek = function seek(key) {
  assert(this.iter, 'Already ended.');

  if (typeof key === 'string')
    key = new Buffer(key, 'utf8');

  if (this.options.reverse)
    this.iter.seekMax(key);
  else
    this.iter.seekMin(key);
};

/**
 * End the iterator. Free up snapshot.
 * @param {FUnction} callback
 */

Iterator.prototype.end = function end(callback) {
  if (this.ended) {
    util.nextTick(function() {
      callback(new Error('Already ended.'));
    });
    return;
  }

  this.ended = true;
  this.iter = null;

  util.nextTick(callback);
};

/**
 * Iterator Options
 * @constructor
 * @ignore
 * @param {Object} options
 */

function IteratorOptions(options) {
  this.keys = true;
  this.values = true;
  this.start = null;
  this.end = null;
  this.gt = false;
  this.lt = false;
  this.keyAsBuffer = true;
  this.valueAsBuffer = true;
  this.reverse = false;
  this.limit = -1;

  if (options)
    this.fromOptions(options);
}

/**
 * Inject properties from options.
 * @private
 * @param {Object} options
 * @returns {IteratorOptions}
 */

IteratorOptions.prototype.fromOptions = function fromOptions(options) {
  if (options.keys != null) {
    assert(typeof options.keys === 'boolean');
    this.keys = options.keys;
  }

  if (options.values != null) {
    assert(typeof options.values === 'boolean');
    this.values = options.values;
  }

  if (options.start != null)
    this.start = options.start;

  if (options.end != null)
    this.end = options.end;

  if (options.gte != null)
    this.start = options.gte;

  if (options.lte != null)
    this.end = options.lte;

  if (options.gt != null) {
    this.gt = true;
    this.start = options.gt;
  }

  if (options.lt != null) {
    this.lt = true;
    this.end = options.lt;
  }

  if (options.keyAsBuffer != null) {
    assert(typeof options.keyAsBuffer === 'boolean');
    this.keyAsBuffer = options.keyAsBuffer;
  }

  if (options.valueAsBuffer != null) {
    assert(typeof options.valueAsBuffer === 'boolean');
    this.valueAsBuffer = options.valueAsBuffer;
  }

  if (options.reverse != null) {
    assert(typeof options.reverse === 'boolean');
    this.reverse = options.reverse;
  }

  if (options.limit != null) {
    assert(typeof options.limit === 'number');
    this.limit = options.limit;
  }

  return this;
};

/*
 * Expose
 */

module.exports = MemoryDB;
