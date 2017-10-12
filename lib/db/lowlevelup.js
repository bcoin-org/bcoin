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

const LOW = Buffer.from([0x00]);
const HIGH = Buffer.from([0xff]);
const keyCache = Object.create(null);

let VERSION_ERROR;

/**
 * Extremely low-level version of levelup.
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
  const Backend = this.backend;

  let db = new Backend(this.location);
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
  const unlock = await this.locker.lock();
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

LowlevelUp.prototype._open = async function _open() {
  if (this.loaded)
    throw new Error('Database is already open.');

  assert(!this.loading);
  assert(!this.closing);
  assert(!this.current);

  this.loading = true;

  try {
    await this.load();
  } catch (e) {
    this.loading = false;
    throw e;
  }

  this.loading = false;
  this.loaded = true;
  this.current = this.batch();
};

/**
 * Close the database.
 * @method
 * @returns {Promise}
 */

LowlevelUp.prototype.close = async function close() {
  const unlock = await this.locker.lock();
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

LowlevelUp.prototype._close = async function _close() {
  if (!this.loaded)
    throw new Error('Database is already closed.');

  assert(!this.loading);
  assert(!this.closing);
  assert(this.current);

  this.loaded = false;
  this.closing = true;
  this.current = null;

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
          resolve(null);
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
 * @returns {LowlevelUp}
 */

LowlevelUp.prototype.put = function put(key, value) {
  if (!value)
    value = LOW;

  this.current.put(key, value);
  return this;
};

/**
 * Remove a record from the database.
 * @param {String|Buffer} key
 * @returns {LowlevelUp}
 */

LowlevelUp.prototype.del = function del(key) {
  this.current.del(key);
  return this;
};

/**
 * Clear current batch.
 * @returns {LowlevelUp}
 */

LowlevelUp.prototype.clear = function clear() {
  this.current.clear();
  return this;
};

/**
 * Commit current batch.
 * @returns {Promise}
 */

LowlevelUp.prototype.write = async function write() {
  try {
    await this.current.write();
  } finally {
    this.current = this.batch();
  }
};

/**
 * Create an atomic batch.
 * @param {Array?} ops
 * @returns {Batch}
 */

LowlevelUp.prototype.batch = function batch(ops) {
  if (!this.loaded)
    throw new Error('Database is closed.');

  return new Batch(this);
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
 * Create a bucket.
 * @param {Number|String|null} id
 * @param {String[]|null} ops
 * @param {Buffer|null} prefix
 */

LowlevelUp.prototype.bucket = function bucket(id, ops, prefix) {
  return new Bucket(this, prefix, id, ops);
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
    start = LOW;

  if (!end)
    end = HIGH;

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
  const value = await this.get(key);
  return value != null;
};

/**
 * Collect all keys from iterator options.
 * @method
 * @param {Object} options - Iterator options.
 * @returns {Promise} - Returns Array.
 */

LowlevelUp.prototype.range = function range(options = {}) {
  const iter = this.iterator({
    gte: options.gte,
    lte: options.lte,
    keys: true,
    values: true
  });
  return this._range(iter, options.parse);
};

/**
 * Collect all keys from iterator options.
 * @method
 * @param {Object} options - Iterator options.
 * @returns {Promise} - Returns Array.
 */

LowlevelUp.prototype._range = async function _range(iter, parse) {
  const items = [];

  while (await iter.next()) {
    const {key, value} = iter;

    if (parse) {
      try {
        const item = parse(key, value);
        if (item)
          items.push(item);
      } catch (e) {
        await iter.end();
        throw e;
      }
      continue;
    }

    items.push(new IteratorItem(key, value));
  }

  return items;
};

/**
 * Collect all keys from iterator options.
 * @method
 * @param {Object} options - Iterator options.
 * @returns {Promise} - Returns Array.
 */

LowlevelUp.prototype.keys = function keys(options = {}) {
  const iter = this.iterator({
    gte: options.gte,
    lte: options.lte,
    keys: true,
    values: false
  });
  return this._keys(iter, options.parse);
};

/**
 * Collect all keys from iterator options.
 * @method
 * @param {Object} options - Iterator options.
 * @returns {Promise} - Returns Array.
 */

LowlevelUp.prototype._keys = async function _keys(iter, parse) {
  const items = [];

  while (await iter.next()) {
    const {key} = iter;

    if (parse) {
      try {
        const item = parse(key);
        if (item)
          items.push(item);
      } catch (e) {
        await iter.end();
        throw e;
      }
      continue;
    }

    items.push(key);
  }

  return items;
};

/**
 * Collect all keys from iterator options.
 * @method
 * @param {Object} options - Iterator options.
 * @returns {Promise} - Returns Array.
 */

LowlevelUp.prototype.values = function values(options = {}) {
  const iter = this.iterator({
    gte: options.gte,
    lte: options.lte,
    keys: false,
    values: true
  });
  return this._values(iter, options.parse);
};

/**
 * Collect all keys from iterator options.
 * @method
 * @param {Object} options - Iterator options.
 * @returns {Promise} - Returns Array.
 */

LowlevelUp.prototype._values = async function _values(iter, parse) {
  const items = [];

  while (await iter.next()) {
    const {value} = iter;

    if (parse) {
      try {
        const item = parse(value);
        if (item)
          items.push(item);
      } catch (e) {
        await iter.end();
        throw e;
      }
      continue;
    }

    items.push(value);
  }

  return items;
};

/**
 * Dump database (for debugging).
 * @method
 * @returns {Promise} - Returns Object.
 */

LowlevelUp.prototype.dump = async function dump() {
  const records = Object.create(null);

  const items = await this.range({
    gte: LOW,
    lte: HIGH
  });

  for (const item of items) {
    const key = item.key.toString('hex');
    const value = item.value.toString('hex');
    records[key] = value;
  }

  return records;
};

/**
 * Write and assert a version number for the database.
 * @param {Buffer|String} key
 * @param {Number} version
 * @returns {Promise}
 */

LowlevelUp.prototype.checkVersion = async function checkVersion(key, version) {
  const data = await this.get(key);

  if (!data) {
    const buf = Buffer.allocUnsafe(4);
    buf.writeUInt32LE(version, 0, true);
    this.put(key, buf);
    await this.write();
    return;
  }

  const num = data.readUInt32LE(0, true);

  if (num !== version)
    throw new Error(VERSION_ERROR);
};

/**
 * Clone the database.
 * @method
 * @param {String} path
 * @returns {Promise}
 */

LowlevelUp.prototype.clone = async function clone(path) {
  if (!this.loaded)
    throw new Error('Database is closed.');

  const options = new LLUOptions(this.options);
  const hwm = 256 << 20;

  options.createIfMissing = true;
  options.errorIfExists = true;

  const tmp = new LowlevelUp(this.backend, path, options);

  await tmp.open();

  let batch = tmp.batch();
  let total = 0;

  const iter = this.iterator({
    keys: true,
    values: true
  });

  while (await iter.next()) {
    const {key, value} = iter;

    batch.put(key, value);
    total += value.length;

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

function Batch(db, bucket) {
  this.batch = db.binding.batch();
}

/**
 * Write a value to the batch.
 * @param {String|Buffer} key
 * @param {Buffer} value
 */

Batch.prototype.put = function put(key, value) {
  if (!value)
    value = LOW;

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
 * @param {Bucket|null} bucket
 */

function Iterator(db, options, bucket) {
  this.options = new IteratorOptions(options, bucket);
  this.iter = db.db.iterator(this.options);
  this.bucket = bucket || null;
  this.key = null;
  this.raw = null;
  this.value = null;
  this.valid = true;
}

/**
 * Seek to the next key.
 * @returns {Promise}
 */

Iterator.prototype.next = function next() {
  return new Promise((resolve, reject) => {
    this.iter.next((err, key, value) => {
      if (err) {
        this.iter.end(() => {
          this.clear();
          reject(err);
        });
        return;
      }

      if (key === undefined && value === undefined) {
        this.iter.end((err) => {
          if (err) {
            reject(err);
            return;
          }
          this.clear();
          resolve(false);
        });
        return;
      }

      this.raw = key;
      this.key = key;
      this.value = value;

      if (this.options.keys) {
        if (key && this.bucket)
          this.key = this.bucket.parse(key);
      }

      resolve(true);
    });
  });
};

/**
 * Clear the iterator.
 */

Iterator.prototype.clear = function clear() {
  this.key = null;
  this.raw = null;
  this.value = null;
  this.valid = false;
};

/**
 * Seek to an arbitrary key.
 * @param {String|Buffer} key
 */

Iterator.prototype.seek = function seek(...args) {
  if (!this.bucket) {
    assert(args.length === 1);
    const [key] = args[0];
    this.iter.seek(key);
    return;
  }

  this.iter.seek(this.bucket.build(args));
};

/**
 * End the iterator.
 * @returns {Promise}
 */

Iterator.prototype.end = function end() {
  return new Promise((resolve, reject) => {
    this.iter.end((err) => {
      if (err) {
        reject(err);
        return;
      }
      this.clear();
      resolve();
    });
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
 * Bucket
 * @ignore
 * @constructor
 * @param {Object} db
 * @param {Buffer|null} prefix
 * @param {Number|String} id
 * @param {String[]|null} ops
 */

function Bucket(db, prefix, id, ops) {
  this.db = db;
  this.id = makeID(id);
  this.key = Key.create(ops);
  this.prefix = makePrefix(prefix);
}

Bucket.prototype.set = function set(...ops) {
  this.key = Key.create(ops);
  return this;
};

Bucket.prototype.parse = function parse(raw) {
  return this.key.parse(raw, this.prefix, this.id);
};

Bucket.prototype.build = function build(args) {
  return this.key.build(args, this.prefix, this.id);
};

Bucket.prototype.gte = function gte() {
  let size = 1;

  if (this.prefix)
    size += this.prefix.length;

  if (this.id !== -1)
    size += 1;

  const key = Buffer.allocUnsafe(size);

  let offset = 0;

  if (this.prefix)
    offset += this.prefix.copy(key, 0);

  if (this.id !== -1) {
    key[offset] = this.id;
    offset += 1;
  }

  key[offset] = 0;

  return key;
};

Bucket.prototype.lt = function lt() {
  let size = 1;

  if (this.prefix)
    size += this.prefix.length;

  const key = Buffer.allocUnsafe(size);

  let offset = 0;

  if (this.prefix)
    offset += this.prefix.copy(key, 0);

  if (this.id !== -1)
    key[offset] = this.id + 1;
  else
    key[offset] = 0xff;

  return key;
};

Bucket.prototype.has = function has(...args) {
  return this.db.has(this.build(args));
};

Bucket.prototype.get = function get(...args) {
  return this.db.get(this.build(args));
};

Bucket.prototype.put = function put() {
  assert(arguments.length >= 1);

  const args = new Array(arguments.length - 1);

  for (let i = 0; i < arguments.length - 1; i++)
    args[i] = arguments[i];

  const value = arguments[arguments.length - 1];

  this.db.put(this.build(args), value);

  return this;
};

Bucket.prototype.del = function del(...args) {
  this.db.del(this.build(args));
  return this;
};

Bucket.prototype.iterator = function iterator(options) {
  return new Iterator(this.db, options, this);
};

Bucket.prototype.range = function range(options = {}) {
  const iter = this.iterator({
    gte: options.gte,
    lte: options.lte,
    keys: true,
    values: true
  });
  return this.db._range(iter, options.parse);
};

Bucket.prototype.keys = function keys(options = {}) {
  const iter = this.iterator({
    gte: options.gte,
    lte: options.lte,
    keys: true,
    values: false
  });
  return this.db._keys(iter, options.parse);
};

Bucket.prototype.values = function values(options = {}) {
  const iter = this.iterator({
    gte: options.gte,
    lte: options.lte,
    keys: false,
    values: true
  });
  return this.db._values(iter, options.parse);
};

/*
 * Key Types
 */

const types = {
  uint8: {
    dynamic: false,
    end: false,
    size(v) {
      return 1;
    },
    read(k, o) {
      assert(o + 1 <= k.length);
      return k[o];
    },
    write(k, v, o) {
      if ((v & 0xff) !== v)
        throw new TypeError();
      assert(o + 1 <= k.length);
      k[o] = v;
      return 1;
    }
  },
  uint16: {
    dynamic: false,
    end: false,
    size(v) {
      return 2;
    },
    read(k, o) {
      assert(o + 2 <= k.length);
      return k.readUInt16BE(o, true);
    },
    write(k, v, o) {
      if ((v & 0xffff) !== v)
        throw new TypeError();
      assert(o + 2 <= k.length);
      k.writeUInt16BE(v, o, true);
      return 2;
    }
  },
  uint32: {
    dynamic: false,
    end: false,
    size(v) {
      return 4;
    },
    read(k, o) {
      assert(o + 4 <= k.length);
      return k.readUInt32BE(o, true);
    },
    write(k, v, o) {
      if ((v >>> 0) !== v)
        throw new TypeError();
      assert(o + 4 <= k.length);
      k.writeUInt32BE(v, o, true);
      return 4;
    }
  },
  hash160: {
    dynamic: false,
    end: false,
    size(v) {
      return 20;
    },
    read(k, o) {
      assert(o + 20 <= k.length);
      return k.toString('hex', o, o + 20);
    },
    write(k, v, o) {
      if (writeHex(k, v, o) !== 20)
        throw new TypeError();
      return 20;
    }
  },
  hash256: {
    dynamic: false,
    end: false,
    size(v) {
      return 32;
    },
    read(k, o) {
      assert(o + 32 <= k.length);
      return k.toString('hex', o, o + 32);
    },
    write(k, v, o) {
      if (writeHex(k, v, o) !== 32)
        throw new TypeError();
      return 32;
    }
  },
  buffer: {
    dynamic: true,
    end: true,
    size(v) {
      return sizeHex(v);
    },
    read(k, o) {
      assert(o + 1 <= k.length);
      return k.slice(o);
    },
    write(k, v, o) {
      const size = sizeHex(v);
      if (writeHex(k, v, o) !== size)
        throw new TypeError();
      return size;
    }
  },
  hash: {
    dynamic: true,
    end: true,
    size(v) {
      return sizeHex(v);
    },
    read(k, o) {
      const size = k.length - o;
      if (size !== 20 && size !== 32)
        throw new Error();
      return k.toString('hex', o);
    },
    write(k, v, o) {
      const size = sizeHex(v);

      if (size !== 20 && size !== 32)
        throw new TypeError();

      if (writeHex(k, v, o) !== size)
        throw new TypeError();

      return size;
    }
  },
  phash: {
    dynamic: true,
    end: false,
    size(v) {
      return 1 + sizeHex(v);
    },
    read(k, o) {
      if (k[o] !== 20 && k[o] !== 32)
        throw new Error();
      assert(o + 1 + k[o] <= k.length);
      return k.toString('hex', o + 1, o + 1 + k[o]);
    },
    write(k, v, o) {
      const size = sizeHex(v);

      if (size !== 20 && size !== 32)
        throw new TypeError();

      k[o] = size;

      if (writeHex(k, v, o + 1, 'hex') !== size)
        throw new TypeError();

      return 1 + size;
    }
  },
  char: {
    dynamic: false,
    end: false,
    size(v) {
      return 1;
    },
    read(k, o) {
      return String.fromCharCode(k[o]);
    },
    write(k, v, o) {
      if (typeof v !== 'string' || v.length !== 1)
        throw new TypeError();
      assert(o + 1 <= k.length);
      k[o] = v.charCodeAt(0);
      return 1;
    }
  },
  string: {
    dynamic: true,
    end: true,
    size(v) {
      assert(typeof v === 'string');
      return Buffer.byteLength(v, 'utf8');
    },
    read(k, o) {
      assert(o + 1 <= k.length);
      return k.toString('utf8', o);
    },
    write(k, v, o) {
      if (typeof v !== 'string')
        throw new TypeError();

      const size = Buffer.byteLength(v, 'utf8');

      if (k.write(v, o, 'utf8') !== size)
        throw new TypeError();

      return size;
    }
  }
};

/**
 * Key
 * @ignore
 * @constructor
 * @param {Buffer|null} prefix
 * @param {String[]|null} ops
 */

function Key(ops = []) {
  assert(Array.isArray(ops));

  this.ops = [];
  this.size = 0;
  this.dynamic = false;
  this.gte = null;
  this.lt = null;
  this.init(ops);
}

Key.create = function create(ops) {
  const hash = ops ? ops.join(':') : '';
  const cache = keyCache[hash];

  if (cache)
    return cache;

  const key = new Key(ops);
  keyCache[hash] = key;

  return key;
};

Key.prototype.init = function init(ops) {
  for (let i = 0; i < ops.length; i++) {
    const name = ops[i];

    assert(typeof name === 'string');

    const op = types[name];

    if (!op)
      throw new Error(`Invalid type name: ${name}.`);

    if (op.dynamic) {
      if (op.end && i !== ops.length - 1)
        throw new Error(`Variable type ${name} precedes end.`);

      this.dynamic = true;
    } else {
      assert(!op.end);
      this.size += op.size();
    }

    this.ops.push(op);
  }
};

Key.prototype.getSize = function getSize(args, prefix, id) {
  assert(args.length === this.ops.length);

  let size = this.size;

  if (prefix)
    size += prefix.length;

  if (id !== -1)
    size += 1;

  if (!this.dynamic)
    return size;

  for (let i = 0; i < args.length; i++) {
    const op = this.ops[i];
    const arg = args[i];
    if (op.dynamic)
      size += op.size(arg);
  }

  return size;
};

Key.prototype.build = function build(args, prefix, id) {
  assert(Array.isArray(args));
  assert(!prefix || Buffer.isBuffer(prefix));

  if (args.length !== this.ops.length)
    throw new Error('Wrong number of arguments passed to key.');

  const size = this.getSize(args, prefix, id);
  const key = Buffer.allocUnsafe(size);

  let offset = 0;

  if (prefix) {
    assert(offset + prefix.length <= key.length);
    offset += prefix.copy(key, 0);
  }

  if (id !== -1) {
    assert(offset + 1 <= key.length);
    key[offset] = id;
    offset += 1;
  }

  for (let i = 0; i < this.ops.length; i++) {
    const op = this.ops[i];
    const arg = args[i];
    offset += op.write(key, arg, offset);
  }

  return key;
};

Key.prototype.parse = function parse(key, prefix, id) {
  assert(Buffer.isBuffer(key));
  assert(!prefix || Buffer.isBuffer(prefix));

  let offset = 0;

  if (prefix) {
    if (key.length < prefix.length)
      throw new Error('Key prefix mismatch.');

    const pre = key.slice(0, prefix.length);

    if (!pre.equals(prefix))
      throw new Error('Key prefix mismatch.');

    offset += prefix.length;
  }

  if (this.ops.length === 0)
    return key.slice(offset);

  if (id !== -1) {
    if (offset >= key.length || key[offset] !== id)
      throw new Error('Key prefix mismatch.');
    offset += 1;
  }

  const args = [];

  for (const op of this.ops) {
    const arg = op.read(key, offset);
    offset += op.size(arg);
    args.push(arg);
  }

  if (args.length === 1)
    return args[0];

  return args;
};

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

  return this;
};

/**
 * Iterator Options
 * @constructor
 * @ignore
 * @param {Object} options
 * @param {Bucket|null} bucket
 */

function IteratorOptions(options, bucket) {
  this.gte = null;
  this.lte = null;
  this.gt = null;
  this.lt = null;
  this.keys = true;
  this.values = false;
  this.fillCache = false;
  this.keyAsBuffer = true;
  this.valueAsBuffer = true;
  this.reverse = false;
  this.highWaterMark = 16 * 1024;

  // Note: do not add this property.
  // this.limit = null;

  this.fromOptions(options || {}, bucket);
}

/**
 * Inject properties from options.
 * @private
 * @param {Object} options
 * @param {Bucket|null} bucket
 * @returns {IteratorOptions}
 */

IteratorOptions.prototype.fromOptions = function fromOptions(options, bucket) {
  assert(options, 'Options are required.');

  if (options.gte != null) {
    if (!bucket) {
      assert(Buffer.isBuffer(options.gte));
      this.gte = options.gte;
    } else {
      this.gte = bucket.build(options.gte);
    }
  }

  if (options.lte != null) {
    if (!bucket) {
      assert(Buffer.isBuffer(options.lte));
      this.lte = options.lte;
    } else {
      this.lte = bucket.build(options.lte);
    }
  }

  if (options.gt != null) {
    if (!bucket) {
      assert(Buffer.isBuffer(options.gt));
      this.gt = options.gt;
    } else {
      this.gt = bucket.build(options.gt);
    }
  }

  if (options.lt != null) {
    if (!bucket) {
      assert(Buffer.isBuffer(options.lt));
      this.lt = options.lt;
    } else {
      this.lt = bucket.build(options.lt);
    }
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

  if (bucket) {
    if (!this.gte && !this.gt)
      this.gte = bucket.gte();

    if (!this.lte && !this.lt)
      this.lt = bucket.lt();
  }

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

function makePrefix(prefix) {
  if (prefix == null)
    return null;

  if (typeof prefix === 'string')
    return Buffer.from(prefix, 'ascii');

  if (typeof prefix === 'number')
    return Buffer.from([prefix]);

  assert(Buffer.isBuffer(prefix));

  return prefix;
}

function makeID(id) {
  if (id == null)
    return -1;

  if (typeof id === 'string') {
    assert(id.length === 1);
    id = id.charCodeAt(0);
  }

  assert((id & 0xff) === id);
  assert(id !== 0xff);

  return id;
}

function writeHex(data, str, off) {
  if (Buffer.isBuffer(str))
    return str.copy(data, off);
  assert(typeof str === 'string');
  return data.write(str, off, 'hex');
}

function sizeHex(data) {
  if (Buffer.isBuffer(data))
    return data.length;
  assert(typeof data === 'string');
  return data.length / 2 | 0;
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
