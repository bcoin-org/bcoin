/*!
 * lowlevelup.js - LevelUP module for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const Lock = require('../utils/lock');
const co = require('../utils/co');
let VERSION_ERROR;

/**
 * Extremely low-level version of levelup.
 * The only levelup feature it provides is
 * error-wrapping.
 *
 * This avoids pulling in extra deps and
 * lowers memory usage.
 *
 * @alias module:db.LowlevelUp
 * @constructor
 * @param {Function} backend - Database backend.
 * @param {String} location - File location.
 * @param {Object?} options - Leveldown options.
 */

function LowlevelUp(backend, location, options) {
  if (!(this instanceof LowlevelUp))
    return new LowlevelUp(backend, location, options);

  assert(typeof backend === 'function', 'Backend is required.');
  assert(typeof location === 'string', 'Filename is required.');

  this.options = new LLUOptions(options);
  this.backend = backend;
  this.location = location;
  this.locker = new Lock();

  this.loading = false;
  this.closing = false;
  this.loaded = false;

  this.db = null;
  this.binding = null;

  this.init();
}

/**
 * Initialize the database.
 * @method
 * @private
 */

LowlevelUp.prototype.init = function init() {
  let backend = this.backend;
  let db = new backend(this.location);
  let binding = db;

  // Stay as close to the metal as possible.
  // We want to make calls to C++ directly.
  while (db.db) {
    // Not a database.
    if (typeof db.db.put !== 'function')
      break;

    // Recursive.
    if (db.db === db)
      break;

    // Go deeper.
    db = db.db;
    binding = db;
  }

  // A lower-level binding.
  if (db.binding)
    binding = db.binding;

  this.db = db;
  this.binding = binding;
};

/**
 * Open the database.
 * @method
 * @returns {Promise}
 */

LowlevelUp.prototype.open = async function open() {
  let unlock = await this.locker.lock();
  try {
    return await this._open();
  } finally {
    unlock();
  }
};

/**
 * Open the database (without a lock).
 * @method
 * @private
 * @returns {Promise}
 */

LowlevelUp.prototype._open = async function open() {
  if (this.loaded)
    throw new Error('Database is already open.');

  assert(!this.loading);
  assert(!this.closing);

  this.loading = true;

  try {
    await this.load();
  } catch (e) {
    this.loading = false;
    throw e;
  }

  this.loading = false;
  this.loaded = true;
};

/**
 * Close the database.
 * @method
 * @returns {Promise}
 */

LowlevelUp.prototype.close = async function close() {
  let unlock = await this.locker.lock();
  try {
    return await this._close();
  } finally {
    unlock();
  }
};

/**
 * Close the database (without a lock).
 * @method
 * @private
 * @returns {Promise}
 */

LowlevelUp.prototype._close = async function close() {
  if (!this.loaded)
    throw new Error('Database is already closed.');

  assert(!this.loading);
  assert(!this.closing);

  this.loaded = false;
  this.closing = true;

  try {
    await this.unload();
  } catch (e) {
    this.loaded = true;
    this.closing = false;
    throw e;
  }

  this.closing = false;
};

/**
 * Open the database.
 * @private
 * @returns {Promise}
 */

LowlevelUp.prototype.load = function load() {
  return new Promise((resolve, reject) => {
    this.binding.open(this.options, co.wrap(resolve, reject));
  });
};

/**
 * Close the database.
 * @private
 * @returns {Promise}
 */

LowlevelUp.prototype.unload = function unload() {
  return new Promise((resolve, reject) => {
    this.binding.close(co.wrap(resolve, reject));
  });
};

/**
 * Destroy the database.
 * @returns {Promise}
 */

LowlevelUp.prototype.destroy = function destroy() {
  return new Promise((resolve, reject) => {
    if (this.loaded || this.closing) {
      reject(new Error('Cannot destroy open database.'));
      return;
    }

    if (!this.backend.destroy) {
      reject(new Error('Cannot destroy (method not available).'));
      return;
    }

    this.backend.destroy(this.location, co.wrap(resolve, reject));
  });
};

/**
 * Repair the database.
 * @returns {Promise}
 */

LowlevelUp.prototype.repair = function repair() {
  return new Promise((resolve, reject) => {
    if (this.loaded || this.closing) {
      reject(new Error('Cannot repair open database.'));
      return;
    }

    if (!this.backend.repair) {
      reject(new Error('Cannot repair (method not available).'));
      return;
    }

    this.backend.repair(this.location, co.wrap(resolve, reject));
  });
};

/**
 * Backup the database.
 * @param {String} path
 * @returns {Promise}
 */

LowlevelUp.prototype.backup = function backup(path) {
  if (!this.binding.backup)
    return this.clone(path);

  return new Promise((resolve, reject) => {
    if (!this.loaded) {
      reject(new Error('Database is closed.'));
      return;
    }
    this.binding.backup(path, co.wrap(resolve, reject));
  });
};

/**
 * Retrieve a record from the database.
 * @param {String|Buffer} key
 * @returns {Promise} - Returns Buffer.
 */

LowlevelUp.prototype.get = function get(key) {
  return new Promise((resolve, reject) => {
    if (!this.loaded) {
      reject(new Error('Database is closed.'));
      return;
    }
    this.binding.get(key, (err, result) => {
      if (err) {
        if (isNotFound(err)) {
          resolve();
          return;
        }
        reject(err);
        return;
      }
      resolve(result);
    });
  });
};

/**
 * Store a record in the database.
 * @param {String|Buffer} key
 * @param {Buffer} value
 * @returns {Promise}
 */

LowlevelUp.prototype.put = function put(key, value) {
  return new Promise((resolve, reject) => {
    if (!this.loaded) {
      reject(new Error('Database is closed.'));
      return;
    }
    this.binding.put(key, value, co.wrap(resolve, reject));
  });
};

/**
 * Remove a record from the database.
 * @param {String|Buffer} key
 * @returns {Promise}
 */

LowlevelUp.prototype.del = function del(key) {
  return new Promise((resolve, reject) => {
    if (!this.loaded) {
      reject(new Error('Database is closed.'));
      return;
    }
    this.binding.del(key, co.wrap(resolve, reject));
  });
};

/**
 * Create an atomic batch.
 * @param {Array?} ops
 * @returns {Batch}
 */

LowlevelUp.prototype.batch = function batch(ops) {
  if (!ops) {
    if (!this.loaded)
      throw new Error('Database is closed.');
    return new Batch(this);
  }

  return new Promise((resolve, reject) => {
    if (!this.loaded) {
      reject(new Error('Database is closed.'));
      return;
    }
    this.binding.batch(ops, co.wrap(resolve, reject));
  });
};

/**
 * Create an iterator.
 * @param {Object} options
 * @returns {Iterator}
 */

LowlevelUp.prototype.iterator = function iterator(options) {
  if (!this.loaded)
    throw new Error('Database is closed.');

  return new Iterator(this, options);
};

/**
 * Get a database property.
 * @param {String} name - Property name.
 * @returns {String}
 */

LowlevelUp.prototype.getProperty = function getProperty(name) {
  if (!this.loaded)
    throw new Error('Database is closed.');

  if (!this.binding.getProperty)
    return '';

  return this.binding.getProperty(name);
};

/**
 * Calculate approximate database size.
 * @param {String|Buffer} start - Start key.
 * @param {String|Buffer} end - End key.
 * @returns {Promise} - Returns Number.
 */

LowlevelUp.prototype.approximateSize = function approximateSize(start, end) {
  return new Promise((resolve, reject) => {
    if (!this.loaded) {
      reject(new Error('Database is closed.'));
      return;
    }

    if (!this.binding.approximateSize) {
      reject(new Error('Cannot get size.'));
      return;
    }

    this.binding.approximateSize(start, end, co.wrap(resolve, reject));
  });
};

/**
 * Compact range of keys.
 * @param {String|Buffer|null} start - Start key.
 * @param {String|Buffer|null} end - End key.
 * @returns {Promise}
 */

LowlevelUp.prototype.compactRange = function compactRange(start, end) {
  if (!start)
    start = Buffer.from([0x00]);

  if (!end)
    end = Buffer.from([0xff]);

  return new Promise((resolve, reject) => {
    if (!this.loaded) {
      reject(new Error('Database is closed.'));
      return;
    }

    if (!this.binding.compactRange) {
      resolve();
      return;
    }

    this.binding.compactRange(start, end, co.wrap(resolve, reject));
  });
};

/**
 * Test whether a key exists.
 * @method
 * @param {String} key
 * @returns {Promise} - Returns Boolean.
 */

LowlevelUp.prototype.has = async function has(key) {
  let value = await this.get(key);
  return value != null;
};

/**
 * Collect all keys from iterator options.
 * @method
 * @param {Object} options - Iterator options.
 * @returns {Promise} - Returns Array.
 */

LowlevelUp.prototype.range = async function range(options) {
  let items = [];
  let parse = options.parse;

  let iter = this.iterator({
    gte: options.gte,
    lte: options.lte,
    keys: true,
    values: true
  });

  for (;;) {
    let item = await iter.next();

    if (!item)
      break;

    if (parse) {
      try {
        item = parse(item.key, item.value);
      } catch (e) {
        await iter.end();
        throw e;
      }
    }

    if (item)
      items.push(item);
  }

  return items;
};

/**
 * Collect all keys from iterator options.
 * @method
 * @param {Object} options - Iterator options.
 * @returns {Promise} - Returns Array.
 */

LowlevelUp.prototype.keys = async function _keys(options) {
  let keys = [];
  let parse = options.parse;

  let iter = this.iterator({
    gte: options.gte,
    lte: options.lte,
    keys: true,
    values: false
  });

  for (;;) {
    let item = await iter.next();
    let key;

    if (!item)
      break;

    key = item.key;

    if (parse) {
      try {
        key = parse(key);
      } catch (e) {
        await iter.end();
        throw e;
      }
    }

    if (key)
      keys.push(key);
  }

  return keys;
};

/**
 * Collect all keys from iterator options.
 * @method
 * @param {Object} options - Iterator options.
 * @returns {Promise} - Returns Array.
 */

LowlevelUp.prototype.values = async function _values(options) {
  let values = [];
  let parse = options.parse;

  let iter = this.iterator({
    gte: options.gte,
    lte: options.lte,
    keys: false,
    values: true
  });

  for (;;) {
    let item = await iter.next();
    let value;

    if (!item)
      break;

    value = item.value;

    if (parse) {
      try {
        value = parse(value);
      } catch (e) {
        await iter.end();
        throw e;
      }
    }

    if (value)
      values.push(value);
  }

  return values;
};

/**
 * Dump database (for debugging).
 * @method
 * @returns {Promise} - Returns Object.
 */

LowlevelUp.prototype.dump = async function dump() {
  let records = {};

  let items = await this.range({
    gte: Buffer.from([0x00]),
    lte: Buffer.from([0xff])
  });

  for (let i = 0; i < items.length; i++) {
    let item = items[i];
    let key = item.key.toString('hex');
    let value = item.value.toString('hex');
    records[key] = value;
  }

  return records;
};

/**
 * Write and assert a version number for the database.
 * @method
 * @param {Number} version
 * @returns {Promise}
 */

LowlevelUp.prototype.checkVersion = async function checkVersion(key, version) {
  let data = await this.get(key);

  if (!data) {
    data = Buffer.allocUnsafe(4);
    data.writeUInt32LE(version, 0, true);
    await this.put(key, data);
    return;
  }

  data = data.readUInt32LE(0, true);

  if (data !== version)
    throw new Error(VERSION_ERROR);
};

/**
 * Clone the database.
 * @method
 * @param {String} path
 * @returns {Promise}
 */

LowlevelUp.prototype.clone = async function clone(path) {
  let options = new LLUOptions(this.options);
  let hwm = 256 << 20;
  let total = 0;
  let tmp, batch, iter;

  if (!this.loaded)
    throw new Error('Database is closed.');

  options.createIfMissing = true;
  options.errorIfExists = true;

  tmp = new LowlevelUp(this.backend, path, options);

  await tmp.open();

  batch = tmp.batch();

  iter = this.iterator({
    keys: true,
    values: true
  });

  for (;;) {
    let item = await iter.next();

    if (!item)
      break;

    batch.put(item.key, item.value);
    total += item.value.length;

    if (total >= hwm) {
      total = 0;
      try {
        await batch.write();
      } catch (e) {
        await iter.end();
        await tmp.close();
        throw e;
      }
      batch = tmp.batch();
    }
  }

  try {
    await batch.write();
  } finally {
    await tmp.close();
  }
};

/**
 * Batch
 * @constructor
 * @ignore
 * @param {LowlevelUp} db
 */

function Batch(db) {
  this.batch = db.binding.batch();
}

/**
 * Write a value to the batch.
 * @param {String|Buffer} key
 * @param {Buffer} value
 */

Batch.prototype.put = function put(key, value) {
  this.batch.put(key, value);
  return this;
};

/**
 * Delete a value from the batch.
 * @param {String|Buffer} key
 */

Batch.prototype.del = function del(key) {
  this.batch.del(key);
  return this;
};

/**
 * Write batch to database.
 * @returns {Promise}
 */

Batch.prototype.write = function write() {
  return new Promise((resolve, reject) => {
    this.batch.write(co.wrap(resolve, reject));
  });
};

/**
 * Clear the batch.
 */

Batch.prototype.clear = function clear() {
  this.batch.clear();
  return this;
};

/**
 * Iterator
 * @constructor
 * @ignore
 * @param {LowlevelUp} db
 * @param {Object} options
 */

function Iterator(db, options) {
  options = new IteratorOptions(options);
  options.keyAsBuffer = db.options.bufferKeys;

  this.iter = db.db.iterator(options);
}

/**
 * Seek to the next key.
 * @returns {Promise}
 */

Iterator.prototype.next = function next() {
  return new Promise((resolve, reject) => {
    this.iter.next((err, key, value) => {
      if (err) {
        this.iter.end(() => reject(err));
        return;
      }

      if (key === undefined && value === undefined) {
        this.iter.end(co.wrap(resolve, reject));
        return;
      }

      resolve(new IteratorItem(key, value));
    });
  });
};

/**
 * Seek to an arbitrary key.
 * @param {String|Buffer} key
 */

Iterator.prototype.seek = function seek(key) {
  this.iter.seek(key);
};

/**
 * End the iterator.
 * @returns {Promise}
 */

Iterator.prototype.end = function end() {
  return new Promise((resolve, reject) => {
    this.iter.end(co.wrap(resolve, reject));
  });
};

/**
 * Iterator Item
 * @ignore
 * @constructor
 * @param {String|Buffer} key
 * @param {String|Buffer} value
 * @property {String|Buffer} key
 * @property {String|Buffer} value
 */

function IteratorItem(key, value) {
  this.key = key;
  this.value = value;
}

/**
 * LowlevelUp Options
 * @constructor
 * @ignore
 * @param {Object} options
 */

function LLUOptions(options) {
  this.createIfMissing = true;
  this.errorIfExists = false;
  this.compression = true;
  this.cacheSize = 8 << 20;
  this.writeBufferSize = 4 << 20;
  this.maxOpenFiles = 64;
  this.maxFileSize = 2 << 20;
  this.paranoidChecks = false;
  this.memory = false;
  this.sync = false;
  this.mapSize = 256 * (1024 << 20);
  this.writeMap = false;
  this.noSubdir = true;
  this.bufferKeys = true;

  if (options)
    this.fromOptions(options);
}

/**
 * Inject properties from options.
 * @private
 * @param {Object} options
 * @returns {LLUOptions}
 */

LLUOptions.prototype.fromOptions = function fromOptions(options) {
  assert(options, 'Options are required.');

  if (options.createIfMissing != null) {
    assert(typeof options.createIfMissing === 'boolean',
      '`createIfMissing` must be a boolean.');
    this.createIfMissing = options.createIfMissing;
  }

  if (options.errorIfExists != null) {
    assert(typeof options.errorIfExists === 'boolean',
      '`errorIfExists` must be a boolean.');
    this.errorIfExists = options.errorIfExists;
  }

  if (options.compression != null) {
    assert(typeof options.compression === 'boolean',
      '`compression` must be a boolean.');
    this.compression = options.compression;
  }

  if (options.cacheSize != null) {
    assert(typeof options.cacheSize === 'number',
      '`cacheSize` must be a number.');
    assert(options.cacheSize >= 0);
    this.cacheSize = Math.floor(options.cacheSize / 2);
    this.writeBufferSize = Math.floor(options.cacheSize / 4);
  }

  if (options.maxFiles != null) {
    assert(typeof options.maxFiles === 'number',
      '`maxFiles` must be a number.');
    assert(options.maxFiles >= 0);
    this.maxOpenFiles = options.maxFiles;
  }

  if (options.maxFileSize != null) {
    assert(typeof options.maxFileSize === 'number',
      '`maxFileSize` must be a number.');
    assert(options.maxFileSize >= 0);
    this.maxFileSize = options.maxFileSize;
  }

  if (options.paranoidChecks != null) {
    assert(typeof options.paranoidChecks === 'boolean',
      '`paranoidChecks` must be a boolean.');
    this.paranoidChecks = options.paranoidChecks;
  }

  if (options.memory != null) {
    assert(typeof options.memory === 'boolean',
      '`memory` must be a boolean.');
    this.memory = options.memory;
  }

  if (options.sync != null) {
    assert(typeof options.sync === 'boolean',
      '`sync` must be a boolean.');
    this.sync = options.sync;
  }

  if (options.mapSize != null) {
    assert(typeof options.mapSize === 'number',
      '`mapSize` must be a number.');
    assert(options.mapSize >= 0);
    this.mapSize = options.mapSize;
  }

  if (options.writeMap != null) {
    assert(typeof options.writeMap === 'boolean',
      '`writeMap` must be a boolean.');
    this.writeMap = options.writeMap;
  }

  if (options.noSubdir != null) {
    assert(typeof options.noSubdir === 'boolean',
      '`noSubdir` must be a boolean.');
    this.noSubdir = options.noSubdir;
  }

  if (options.bufferKeys != null) {
    assert(typeof options.bufferKeys === 'boolean',
      '`bufferKeys` must be a boolean.');
    this.bufferKeys = options.bufferKeys;
  }

  return this;
};

/**
 * Iterator Options
 * @constructor
 * @ignore
 * @param {Object} options
 */

function IteratorOptions(options) {
  this.gte = null;
  this.lte = null;
  this.keys = true;
  this.values = false;
  this.fillCache = false;
  this.keyAsBuffer = true;
  this.valueAsBuffer = true;
  this.reverse = false;
  this.highWaterMark = 16 * 1024;

  // Note: do not add this property.
  // this.limit = null;

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
  assert(options, 'Options are required.');

  if (options.gte != null) {
    assert(Buffer.isBuffer(options.gte) || typeof options.gte === 'string');
    this.gte = options.gte;
  }

  if (options.lte != null) {
    assert(Buffer.isBuffer(options.lte) || typeof options.lte === 'string');
    this.lte = options.lte;
  }

  if (options.keys != null) {
    assert(typeof options.keys === 'boolean');
    this.keys = options.keys;
  }

  if (options.values != null) {
    assert(typeof options.values === 'boolean');
    this.values = options.values;
  }

  if (options.fillCache != null) {
    assert(typeof options.fillCache === 'boolean');
    this.fillCache = options.fillCache;
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
    assert(options.limit >= 0);
    this.limit = options.limit;
  }

  if (!this.keys && !this.values)
    throw new Error('Keys and/or values must be chosen.');

  return this;
};

/*
 * Helpers
 */

function isNotFound(err) {
  if (!err)
    return false;

  return err.notFound
    || err.type === 'NotFoundError'
    || /not\s*found/i.test(err.message);
}

VERSION_ERROR = 'Warning:'
  + ' Your database does not match the current database version.'
  + ' This is likely because the database layout or serialization'
  + ' format has changed drastically. If you want to dump your'
  + ' data, downgrade to your previous version first. If you do'
  + ' not think you should be seeing this error, post an issue on'
  + ' the repo.';

/*
 * Expose
 */

module.exports = LowlevelUp;
