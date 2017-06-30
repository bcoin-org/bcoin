/*!
 * memdb.js - in-memory database for bcoin
 * Copyright (c) 2016-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const RBT = require('../utils/rbt');
const DUMMY = Buffer.alloc(0);

/**
 * In memory database for bcoin
 * using a red-black tree backend.
 * @alias module:db.MemDB
 * @constructor
 * @param {String?} location - Phony location.
 * @param {Object?} options
 * @param {Function} options.compare - Comparator.
 */

function MemDB(location) {
  if (!(this instanceof MemDB))
    return new MemDB(location);

  this.location = location || 'memory';
  this.options = {};
  this.tree = new RBT(cmp, true);
}

/**
 * Do a key lookup.
 * @private
 * @param {Buffer|String} key
 * @returns {Buffer?} value
 */

MemDB.prototype.search = function search(key) {
  let node;

  if (typeof key === 'string')
    key = Buffer.from(key, 'utf8');

  assert(Buffer.isBuffer(key), 'Key must be a Buffer.');

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

MemDB.prototype.insert = function insert(key, value) {
  if (typeof key === 'string')
    key = Buffer.from(key, 'utf8');

  if (typeof value === 'string')
    value = Buffer.from(value, 'utf8');

  if (value == null)
    value = DUMMY;

  assert(Buffer.isBuffer(key), 'Key must be a Buffer.');
  assert(Buffer.isBuffer(value), 'Value must be a Buffer.');

  return this.tree.insert(key, value) != null;
};

/**
 * Remove a record.
 * @private
 * @param {Buffer|String} key
 * @returns {Boolean}
 */

MemDB.prototype.remove = function remove(key) {
  if (typeof key === 'string')
    key = Buffer.from(key, 'utf8');

  assert(Buffer.isBuffer(key), 'Key must be a Buffer.');

  return this.tree.remove(key) != null;
};

/**
 * Traverse between a range of keys and collect records.
 * @private
 * @param {Buffer} min
 * @param {Buffer} max
 * @returns {RBTData[]} Records.
 */

MemDB.prototype.range = function range(min, max) {
  if (typeof min === 'string')
    min = Buffer.from(min, 'utf8');

  if (typeof max === 'string')
    max = Buffer.from(max, 'utf8');

  assert(!min || Buffer.isBuffer(min), 'Key must be a Buffer.');
  assert(!max || Buffer.isBuffer(max), 'Key must be a Buffer.');

  return this.tree.range(min, max);
};

/**
 * Open the database (leveldown method).
 * @param {Object?} options
 * @param {Function} callback
 */

MemDB.prototype.open = function open(options, callback) {
  if (!callback) {
    callback = options;
    options = null;
  }

  if (!options)
    options = {};

  this.options = options;

  setImmediate(callback);
};

/**
 * Close the database (leveldown method).
 * @param {Function} callback
 */

MemDB.prototype.close = function close(callback) {
  setImmediate(callback);
};

/**
 * Retrieve a record (leveldown method).
 * @param {Buffer|String} key
 * @param {Object?} options
 * @param {Function} callback - Returns Bufer.
 */

MemDB.prototype.get = function get(key, options, callback) {
  let value;

  if (!callback) {
    callback = options;
    options = null;
  }

  if (!options)
    options = {};

  value = this.search(key);

  if (!value) {
    let err = new Error('MEMDB_NOTFOUND: Key not found.');
    err.notFound = true;
    err.type = 'NotFoundError';
    setImmediate(() => callback(err));
    return;
  }

  if (options.asBuffer === false)
    value = value.toString('utf8');

  setImmediate(() => callback(null, value));
};

/**
 * Insert a record (leveldown method).
 * @param {Buffer|String} key
 * @param {Buffer} value
 * @param {Object?} options
 * @param {Function} callback
 */

MemDB.prototype.put = function put(key, value, options, callback) {
  if (!callback) {
    callback = options;
    options = null;
  }

  this.insert(key, value);

  setImmediate(callback);
};

/**
 * Remove a record (leveldown method).
 * @param {Buffer|String} key
 * @param {Object?} options
 * @param {Function} callback
 */

MemDB.prototype.del = function del(key, options, callback) {
  if (!callback) {
    callback = options;
    options = null;
  }

  this.remove(key);

  setImmediate(callback);
};

/**
 * Create an atomic batch (leveldown method).
 * @see Leveldown.Batch
 * @param {Object[]?} ops
 * @param {Object?} options
 * @param {Function} callback
 */

MemDB.prototype.batch = function _batch(ops, options, callback) {
  let batch;

  if (!callback) {
    callback = options;
    options = null;
  }

  batch = new Batch(this, options);

  if (ops) {
    batch.ops = ops;
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

MemDB.prototype.iterator = function iterator(options) {
  return new Iterator(this, options);
};

/**
 * Get a database property (leveldown method) (NOP).
 * @param {String} name - Property name.
 * @returns {String}
 */

MemDB.prototype.getProperty = function getProperty(name) {
  return '';
};

/**
 * Calculate approximate database size (leveldown method).
 * @param {Buffer|String} start - Start key.
 * @param {Buffer|String} end - End key.
 * @param {Function} callback - Returns Number.
 */

MemDB.prototype.approximateSize = function approximateSize(start, end, callback) {
  let items = this.range(start, end);
  let size = 0;

  for (let item of items) {
    size += item.key.length;
    size += item.value.length;
  }

  setImmediate(() => callback(null, size));
};

/**
 * Destroy the database (leveldown function) (NOP).
 * @param {String} location
 * @param {Function} callback
 */

MemDB.destroy = function destroy(location, callback) {
  setImmediate(callback);
};

/**
 * Repair the database (leveldown function) (NOP).
 * @param {String} location
 * @param {Function} callback
 */

MemDB.repair = function repair(location, callback) {
  setImmediate(callback);
};

/**
 * Batch
 * @constructor
 * @ignore
 * @private
 * @param {MemDB} db
 * @param {Object?} options
 */

function Batch(db, options) {
  this.options = options || {};
  this.ops = [];
  this.db = db;
  this.written = false;
}

/**
 * Insert a record.
 * @param {Buffer|String} key
 * @param {Buffer} value
 */

Batch.prototype.put = function put(key, value) {
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
  if (this.written) {
    setImmediate(() => callback(new Error('Already written.')));
    return;
  }

  for (let op of this.ops) {
    switch (op.type) {
      case 'put':
        this.db.insert(op.key, op.value);
        break;
      case 'del':
        this.db.remove(op.key);
        break;
      default:
        setImmediate(() => callback(new Error('Bad op.')));
        return;
    }
  }

  this.ops = [];
  this.written = true;

  setImmediate(callback);

  return this;
};

/**
 * Clear batch of all ops.
 */

Batch.prototype.clear = function clear() {
  assert(!this.written, 'Already written.');
  this.ops = [];
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
  let snapshot = this.db.tree.snapshot();
  let iter = this.db.tree.iterator(snapshot);

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

Iterator.prototype.next = function next(callback) {
  let options = this.options;
  let iter = this.iter;
  let key, value, result;

  if (!this.iter) {
    setImmediate(() => callback(new Error('Cannot call next.')));
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
    setImmediate(callback);
    return;
  }

  if (options.limit !== -1) {
    if (this.total >= options.limit) {
      this.iter = null;
      setImmediate(callback);
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

  setImmediate(() => callback(null, key, value));
};

/**
 * Seek to a key gte to `key`.
 * @param {String|Buffer} key
 */

Iterator.prototype.seek = function seek(key) {
  assert(this.iter, 'Already ended.');

  if (typeof key === 'string')
    key = Buffer.from(key, 'utf8');

  assert(Buffer.isBuffer(key), 'Key must be a Buffer.');

  if (this.options.reverse)
    this.iter.seekMax(key);
  else
    this.iter.seekMin(key);
};

/**
 * End the iterator. Free up snapshot.
 * @param {Function} callback
 */

Iterator.prototype.end = function end(callback) {
  if (this.ended) {
    setImmediate(() => callback(new Error('Already ended.')));
    return;
  }

  this.ended = true;
  this.iter = null;

  setImmediate(callback);
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

  if (this.start != null) {
    if (typeof this.start === 'string')
      this.start = Buffer.from(this.start, 'utf8');
    assert(Buffer.isBuffer(this.start), '`start` must be a Buffer.');
  }

  if (this.end != null) {
    if (typeof this.end === 'string')
      this.end = Buffer.from(this.end, 'utf8');
    assert(Buffer.isBuffer(this.end), '`end` must be a Buffer.');
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
 * Helpers
 */

function cmp(a, b) {
  return a.compare(b);
}

/*
 * Expose
 */

module.exports = MemDB;
