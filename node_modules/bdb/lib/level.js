/**
 * level.js - database backend for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const binding = require('loady')('leveldown', __dirname);
const OPTIONS = Object.create(null);

/**
 * LevelDOWN
 */

class LevelDOWN {
  constructor(location) {
    assert(typeof location === 'string');

    this.location = location;
    this.context = binding.db_init();
  }

  open(options, callback) {
    if (options == null)
      options = OPTIONS;

    assert(options && typeof options === 'object');
    assert(typeof callback === 'function');

    binding.db_open(this.context, this.location, options, callback);
  }

  close(callback) {
    assert(typeof callback === 'function');

    binding.db_close(this.context, callback);
  }

  put(key, value, callback) {
    assert(isValue(key));
    assert(isValue(value));
    assert(typeof callback === 'function');

    binding.db_put(this.context, key, value, OPTIONS, callback);
  }

  get(key, callback) {
    assert(isValue(key));
    assert(typeof callback === 'function');

    binding.db_get(this.context, key, OPTIONS, callback);
  }

  del(key, callback) {
    assert(isValue(key));
    assert(typeof callback === 'function');

    binding.db_del(this.context, key, OPTIONS, callback);
  }

  batch(ops, callback) {
    if (ops == null)
      return new Batch(this);

    assert(Array.isArray(ops));
    assert(typeof callback === 'function');

    for (const op of ops) {
      assert(op && typeof op === 'object');
      assert(op.type === 'put' || op.type === 'del');
      assert(isValue(op.key));

      if (op.type === 'put')
        assert(isValue(op.value));
    }

    binding.batch_do(this.context, ops, OPTIONS, callback);

    return undefined;
  }

  approximateSize(start, end, callback) {
    assert(isValue(start));
    assert(isValue(end));
    assert(typeof callback === 'function');

    binding.db_approximate_size(this.context, start, end, callback);
  }

  compactRange(start, end, callback) {
    assert(isValue(start));
    assert(isValue(end));
    assert(typeof callback === 'function');

    binding.db_compact_range(this.context, start, end, callback);
  }

  getProperty(property) {
    assert(typeof property === 'string');

    return binding.db_get_property(this.context, property);
  }

  iterator(options) {
    if (options == null)
      options = OPTIONS;

    assert(options && typeof options === 'object');

    return new Iterator(this, options);
  }

  static destroy(location, callback) {
    assert(typeof location === 'string');
    assert(typeof callback === 'function');

    binding.destroy_db(location, callback);
  }

  static repair(location, callback) {
    assert(typeof location === 'string');
    assert(typeof callback === 'function');

    binding.repair_db(location, callback);
  }
}

/*
 * Static
 */

LevelDOWN.leveldown = true;

/**
 * Batch
 */

class Batch {
  constructor(db) {
    this.context = binding.batch_init(db.context);
  }

  put(key, value) {
    assert(isValue(key));
    assert(isValue(value));

    binding.batch_put(this.context, key, value);
  }

  del(key) {
    assert(isValue(key));

    binding.batch_del(this.context, key);
  }

  clear() {
    binding.batch_clear(this.context);
  }

  write(callback) {
    assert(typeof callback === 'function');

    binding.batch_write(this.context, OPTIONS, callback);
  }
}

/**
 * Iterator
 */

class Iterator {
  constructor(db, options) {
    this.context = binding.iterator_init(db.context, options);
  }

  seek(target) {
    assert(isValue(target));

    if (target.length === 0)
      throw new Error('cannot seek() to an empty target');

    binding.iterator_seek(this.context, target);
  }

  next(callback) {
    assert(typeof callback === 'function');

    binding.iterator_next(this.context, callback);
  }

  end(callback) {
    assert(typeof callback === 'function');

    binding.iterator_end(this.context, callback);
  }
}

/*
 * Helpers
 */

function assert(ok) {
  if (!ok)
    throw new TypeError('Invalid argument.');
}

function isValue(key) {
  return Buffer.isBuffer(key) || typeof key === 'string';
}

/*
 * Expose
 */

module.exports = LevelDOWN;
