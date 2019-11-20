/*!
 * memdb.js - in-memory database for bcoin
 * Copyright (c) 2016-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');
const RBT = require('./rbt');
const DUMMY = Buffer.alloc(0);

/**
 * MemDB
 */

class MemDB {
  /**
   * Create a memdb.
   * @constructor
   * @param {String?} location - Phony location.
   * @param {Object?} options
   * @param {Function} options.compare - Comparator.
   */

  constructor(location) {
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

  search(key) {
    if (typeof key === 'string')
      key = Buffer.from(key, 'utf8');

    assert(Buffer.isBuffer(key), 'Key must be a Buffer.');

    const node = this.tree.search(key);

    if (!node)
      return undefined;

    return node.value;
  }

  /**
   * Insert a record.
   * @private
   * @param {Buffer|String} key
   * @param {Buffer} value
   */

  insert(key, value) {
    if (typeof key === 'string')
      key = Buffer.from(key, 'utf8');

    if (typeof value === 'string')
      value = Buffer.from(value, 'utf8');

    if (value == null)
      value = DUMMY;

    assert(Buffer.isBuffer(key), 'Key must be a Buffer.');
    assert(Buffer.isBuffer(value), 'Value must be a Buffer.');

    return this.tree.insert(key, value) != null;
  }

  /**
   * Remove a record.
   * @private
   * @param {Buffer|String} key
   * @returns {Boolean}
   */

  remove(key) {
    if (typeof key === 'string')
      key = Buffer.from(key, 'utf8');

    assert(Buffer.isBuffer(key), 'Key must be a Buffer.');

    return this.tree.remove(key) != null;
  }

  /**
   * Traverse between a range of keys and collect records.
   * @private
   * @param {Buffer} min
   * @param {Buffer} max
   * @returns {RBTData[]} Records.
   */

  range(min, max) {
    if (typeof min === 'string')
      min = Buffer.from(min, 'utf8');

    if (typeof max === 'string')
      max = Buffer.from(max, 'utf8');

    assert(!min || Buffer.isBuffer(min), 'Key must be a Buffer.');
    assert(!max || Buffer.isBuffer(max), 'Key must be a Buffer.');

    return this.tree.range(min, max);
  }

  /**
   * Open the database (leveldown method).
   * @param {Object?} options
   * @param {Function} callback
   */

  open(options, callback) {
    if (!callback) {
      callback = options;
      options = null;
    }

    if (!options)
      options = {};

    this.options = options;

    setImmediate(callback);
  }

  /**
   * Close the database (leveldown method).
   * @param {Function} callback
   */

  close(callback) {
    setImmediate(callback);
  }

  /**
   * Retrieve a record (leveldown method).
   * @param {Buffer|String} key
   * @param {Object?} options
   * @param {Function} callback - Returns Buffer.
   */

  get(key, options, callback) {
    if (!callback) {
      callback = options;
      options = null;
    }

    if (!options)
      options = {};

    let value = this.search(key);

    if (!value) {
      const err = new Error('MEMDB_NOTFOUND: Key not found.');
      err.notFound = true;
      err.type = 'NotFoundError';
      setImmediate(() => callback(err));
      return;
    }

    if (options.asBuffer === false)
      value = value.toString('utf8');

    setImmediate(() => callback(null, value));
  }

  /**
   * Insert a record (leveldown method).
   * @param {Buffer|String} key
   * @param {Buffer} value
   * @param {Object?} options
   * @param {Function} callback
   */

  put(key, value, options, callback) {
    if (!callback) {
      callback = options;
      options = null;
    }

    this.insert(key, value);

    setImmediate(callback);
  }

  /**
   * Remove a record (leveldown method).
   * @param {Buffer|String} key
   * @param {Object?} options
   * @param {Function} callback
   */

  del(key, options, callback) {
    if (!callback) {
      callback = options;
      options = null;
    }

    this.remove(key);

    setImmediate(callback);
  }

  /**
   * Create an atomic batch (leveldown method).
   * @see Leveldown.Batch
   * @param {Object[]?} ops
   * @param {Object?} options
   * @param {Function} callback
   */

  batch(ops, options, callback) {
    if (!callback) {
      callback = options;
      options = null;
    }

    const b = new Batch(this, options);

    if (ops) {
      b.ops = ops;
      b.write(callback);
      return undefined;
    }

    return b;
  }

  /**
   * Create an iterator (leveldown method).
   * @param {Object} options - See {Leveldown.Iterator}.
   * @returns {Leveldown.Iterator}.
   */

  iterator(options) {
    return new Iterator(this, options);
  }

  /**
   * Get a database property (leveldown method) (NOP).
   * @param {String} name - Property name.
   * @returns {String}
   */

  getProperty(name) {
    return '';
  }

  /**
   * Calculate approximate database size (leveldown method).
   * @param {Buffer|String} start - Start key.
   * @param {Buffer|String} end - End key.
   * @param {Function} callback - Returns Number.
   */

  approximateSize(start, end, callback) {
    const items = this.range(start, end);

    let size = 0;

    for (const item of items) {
      size += item.key.length;
      size += item.value.length;
    }

    setImmediate(() => callback(null, size));
  }

  /**
   * Destroy the database (leveldown function) (NOP).
   * @param {String} location
   * @param {Function} callback
   */

  static destroy(location, callback) {
    setImmediate(callback);
  }

  /**
   * Repair the database (leveldown function) (NOP).
   * @param {String} location
   * @param {Function} callback
   */

  static repair(location, callback) {
    setImmediate(callback);
  }
}

/**
 * Batch
 */

class Batch {
  /**
   * Create a batch.
   * @constructor
   * @ignore
   * @param {MemDB} db
   * @param {Object?} options
   */

  constructor(db, options) {
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

  put(key, value) {
    assert(!this.written, 'Already written.');
    this.ops.push(new BatchOp('put', key, value));
    return this;
  }

  /**
   * Remove a record.
   * @param {Buffer|String} key
   */

  del(key) {
    assert(!this.written, 'Already written.');
    this.ops.push(new BatchOp('del', key));
    return this;
  }

  /**
   * Commit the batch.
   * @param {Function} callback
   */

  write(callback) {
    if (this.written) {
      setImmediate(() => callback(new Error('Already written.')));
      return this;
    }

    for (const op of this.ops) {
      switch (op.type) {
        case 'put':
          this.db.insert(op.key, op.value);
          break;
        case 'del':
          this.db.remove(op.key);
          break;
        default:
          setImmediate(() => callback(new Error('Bad op.')));
          return this;
      }
    }

    this.ops = [];
    this.written = true;

    setImmediate(callback);

    return this;
  }

  /**
   * Clear batch of all ops.
   */

  clear() {
    assert(!this.written, 'Already written.');
    this.ops = [];
    return this;
  }
}

/**
 * Batch Op
 */

class BatchOp {
  /**
   * Create a batch op.
   * @constructor
   * @ignore
   * @param {String} type
   * @param {Buffer} key
   * @param {Buffer|null} value
   */

  constructor(type, key, value) {
    this.type = type;
    this.key = key;
    this.value = value;
  }
}

/**
 * Iterator
 */

class Iterator {
  /**
   * Create an iterator.
   * @constructor
   * @ignore
   * @param {RBT} db
   * @param {Object?} options
   */

  constructor(db, options) {
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

  init() {
    const snapshot = this.db.tree.snapshot();
    const iter = this.db.tree.iterator(snapshot);

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
  }

  /**
   * Seek to the next key.
   * @param {Function} callback
   */

  next(callback) {
    const options = this.options;
    const iter = this.iter;

    if (!this.iter) {
      setImmediate(() => callback(new Error('Cannot call next.')));
      return;
    }

    let result;
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

    let key = iter.key;
    let value = iter.value;

    if (!options.keys)
      key = DUMMY;

    if (!options.values)
      value = DUMMY;

    if (!options.keyAsBuffer)
      key = key.toString('utf8');

    if (!options.valueAsBuffer)
      value = value.toString('utf8');

    setImmediate(() => callback(null, key, value));
  }

  /**
   * Seek to a key gte to `key`.
   * @param {String|Buffer} key
   */

  seek(key) {
    assert(this.iter, 'Already ended.');

    if (typeof key === 'string')
      key = Buffer.from(key, 'utf8');

    assert(Buffer.isBuffer(key), 'Key must be a Buffer.');

    if (this.options.reverse)
      this.iter.seekMax(key);
    else
      this.iter.seekMin(key);
  }

  /**
   * End the iterator. Free up snapshot.
   * @param {Function} callback
   */

  end(callback) {
    if (this.ended) {
      setImmediate(() => callback(new Error('Already ended.')));
      return;
    }

    this.ended = true;
    this.iter = null;

    setImmediate(callback);
  }
}

/**
 * Iterator Options
 */

class IteratorOptions {
  /**
   * Create iterator options.
   * @constructor
   * @ignore
   * @param {Object} options
   */

  constructor(options) {
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

  fromOptions(options) {
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
  }
}

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
