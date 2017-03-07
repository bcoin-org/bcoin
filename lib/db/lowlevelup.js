/*!
 * lowlevelup.js - LevelUP module for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var util = require('../utils/util');
var Lock = require('../utils/lock');
var co = require('../utils/co');
var VERSION_ERROR;

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
 * @param {String} file - Location.
 * @param {Object} options - Leveldown options.
 */

function LowlevelUp(file, options) {
  if (!(this instanceof LowlevelUp))
    return new LowlevelUp(file, options);

  assert(typeof file === 'string', 'Filename is required.');
  assert(options, 'Options are required.');
  assert(options.db, 'Database backend is required.');

  this.options = options;
  this.backend = options.db;
  this.location = file;
  this.bufferKeys = options.bufferKeys === true;
  this.locker = new Lock();

  this.loading = false;
  this.closing = false;
  this.loaded = false;

  this.db = new options.db(file);

  // Stay as close to the metal as possible.
  // We want to make calls to C++ directly.
  while (this.db.db && this.db.db.put && this.db.db !== this.db)
    this.db = this.db.db;

  this.binding = this.db;

  if (this.db.binding)
    this.binding = this.db.binding;
}

/**
 * Open the database.
 * @returns {Promise}
 */

LowlevelUp.prototype.open = co(function* open() {
  var unlock = yield this.locker.lock();
  try {
    return yield this._open();
  } finally {
    unlock();
  }
});

/**
 * Close the database.
 * @returns {Promise}
 */

LowlevelUp.prototype.close = co(function* close() {
  var unlock = yield this.locker.lock();
  try {
    return yield this._close();
  } finally {
    unlock();
  }
});

/**
 * Open the database (without a lock).
 * @private
 * @returns {Promise}
 */

LowlevelUp.prototype._open = co(function* open() {
  if (this.loaded)
    throw new Error('Database is already open.');

  assert(!this.loading);
  assert(!this.closing);

  this.loading = true;

  try {
    yield this.load();
  } catch (e) {
    this.loading = false;
    throw e;
  }

  this.loading = false;
  this.loaded = true;
});

/**
 * Close the database (without a lock).
 * @private
 * @returns {Promise}
 */

LowlevelUp.prototype._close = co(function* close() {
  if (!this.loaded)
    throw new Error('Database is already closed.');

  assert(!this.loading);
  assert(!this.closing);

  this.loaded = false;
  this.closing = true;

  try {
    yield this.unload();
  } catch (e) {
    this.loaded = true;
    this.closing = false;
    throw e;
  }

  this.closing = false;
});

/**
 * Open the database.
 * @private
 * @returns {Promise}
 */

LowlevelUp.prototype.load = function load() {
  var self = this;
  return new Promise(function(resolve, reject) {
    self.binding.open(self.options, co.wrap(resolve, reject));
  });
};

/**
 * Close the database.
 * @private
 * @returns {Promise}
 */

LowlevelUp.prototype.unload = function unload() {
  var self = this;
  return new Promise(function(resolve, reject) {
    self.binding.close(co.wrap(resolve, reject));
  });
};

/**
 * Destroy the database.
 * @returns {Promise}
 */

LowlevelUp.prototype.destroy = function destroy() {
  var self = this;

  return new Promise(function(resolve, reject) {
    if (self.loaded || self.closing) {
      reject(new Error('Cannot destroy open database.'));
      return;
    }

    if (!self.backend.destroy) {
      reject(new Error('Cannot destroy (method not available).'));
      return;
    }

    self.backend.destroy(self.location, co.wrap(resolve, reject));
  });
};

/**
 * Repair the database.
 * @returns {Promise}
 */

LowlevelUp.prototype.repair = function repair() {
  var self = this;

  return new Promise(function(resolve, reject) {
    if (self.loaded || self.closing) {
      reject(new Error('Cannot repair open database.'));
      return;
    }

    if (!self.backend.repair) {
      reject(new Error('Cannot repair (method not available).'));
      return;
    }

    self.backend.repair(self.location, co.wrap(resolve, reject));
  });
};

/**
 * Backup the database.
 * @param {String} path
 * @returns {Promise}
 */

LowlevelUp.prototype.backup = function backup(path) {
  var self = this;

  if (!this.binding.backup)
    return this.clone(path);

  return new Promise(function(resolve, reject) {
    if (!self.loaded) {
      reject(new Error('Database is closed.'));
      return;
    }
    self.binding.backup(path, co.wrap(resolve, reject));
  });
};

/**
 * Retrieve a record from the database.
 * @param {String|Buffer} key
 * @returns {Promise} - Returns Buffer.
 */

LowlevelUp.prototype.get = function get(key) {
  var self = this;
  return new Promise(function(resolve, reject) {
    if (!self.loaded) {
      reject(new Error('Database is closed.'));
      return;
    }
    self.binding.get(key, function(err, result) {
      if (err) {
        if (isNotFound(err))
          return resolve();
        return reject(err);
      }
      return resolve(result);
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
  var self = this;
  return new Promise(function(resolve, reject) {
    if (!self.loaded) {
      reject(new Error('Database is closed.'));
      return;
    }
    self.binding.put(key, value, co.wrap(resolve, reject));
  });
};

/**
 * Remove a record from the database.
 * @param {String|Buffer} key
 * @returns {Promise}
 */

LowlevelUp.prototype.del = function del(key) {
  var self = this;
  return new Promise(function(resolve, reject) {
    if (!self.loaded) {
      reject(new Error('Database is closed.'));
      return;
    }
    self.binding.del(key, co.wrap(resolve, reject));
  });
};

/**
 * Create an atomic batch.
 * @param {Array?} ops
 * @returns {Batch}
 */

LowlevelUp.prototype.batch = function batch(ops) {
  var self = this;

  if (!ops) {
    if (!this.loaded)
      throw new Error('Database is closed.');
    return new Batch(this);
  }

  return new Promise(function(resolve, reject) {
    if (!self.loaded) {
      reject(new Error('Database is closed.'));
      return;
    }
    self.binding.batch(ops, co.wrap(resolve, reject));
  });
};

/**
 * Create an iterator.
 * @param {Object} options
 * @returns {Iterator}
 */

LowlevelUp.prototype.iterator = function iterator(options) {
  var opt;

  if (!this.loaded)
    throw new Error('Database is closed.');

  opt = {
    gte: options.gte,
    lte: options.lte,
    keys: options.keys !== false,
    values: options.values || false,
    fillCache: options.fillCache || false,
    keyAsBuffer: this.bufferKeys,
    valueAsBuffer: true,
    reverse: options.reverse || false,
    highWaterMark: options.highWaterMark || 16 * 1024
  };

  // Workaround for a leveldown
  // bug I haven't fixed yet.
  if (options.limit != null)
    opt.limit = options.limit;

  if (options.keyAsBuffer != null)
    opt.keyAsBuffer = options.keyAsBuffer;

  assert(opt.keys || opt.values, 'Keys and/or values must be chosen.');

  return new Iterator(this, opt);
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
 * @param {String} start - Start key.
 * @param {String} end - End key.
 * @returns {Promise} - Returns Number.
 */

LowlevelUp.prototype.approximateSize = function approximateSize(start, end) {
  var self = this;

  return new Promise(function(resolve, reject) {
    if (!self.loaded) {
      reject(new Error('Database is closed.'));
      return;
    }

    if (!self.binding.approximateSize) {
      reject(new Error('Cannot get size.'));
      return;
    }

    self.binding.approximateSize(start, end, co.wrap(resolve, reject));
  });
};

/**
 * Test whether a key exists.
 * @method
 * @param {String} key
 * @returns {Promise} - Returns Boolean.
 */

LowlevelUp.prototype.has = co(function* has(key) {
  var value = yield this.get(key);
  return value != null;
});

/**
 * Collect all keys from iterator options.
 * @method
 * @param {Object} options - Iterator options.
 * @returns {Promise} - Returns Array.
 */

LowlevelUp.prototype.range = co(function* range(options) {
  var items = [];
  var parse = options.parse;
  var iter, item;

  iter = this.iterator({
    gte: options.gte,
    lte: options.lte,
    keys: true,
    values: true
  });

  for (;;) {
    item = yield iter.next();

    if (!item)
      break;

    if (parse) {
      try {
        item = parse(item.key, item.value);
      } catch (e) {
        yield iter.end();
        throw e;
      }
    }

    if (item)
      items.push(item);
  }

  return items;
});

/**
 * Collect all keys from iterator options.
 * @method
 * @param {Object} options - Iterator options.
 * @returns {Promise} - Returns Array.
 */

LowlevelUp.prototype.keys = co(function* keys(options) {
  var keys = [];
  var parse = options.parse;
  var iter, item, key;

  iter = this.iterator({
    gte: options.gte,
    lte: options.lte,
    keys: true,
    values: false
  });

  for (;;) {
    item = yield iter.next();

    if (!item)
      break;

    key = item.key;

    if (parse) {
      try {
        key = parse(key);
      } catch (e) {
        yield iter.end();
        throw e;
      }
    }

    if (key)
      keys.push(key);
  }

  return keys;
});

/**
 * Collect all keys from iterator options.
 * @method
 * @param {Object} options - Iterator options.
 * @returns {Promise} - Returns Array.
 */

LowlevelUp.prototype.values = co(function* values(options) {
  var values = [];
  var parse = options.parse;
  var iter, item, value;

  iter = this.iterator({
    gte: options.gte,
    lte: options.lte,
    keys: false,
    values: true
  });

  for (;;) {
    item = yield iter.next();

    if (!item)
      break;

    value = item.value;

    if (parse) {
      try {
        value = parse(value);
      } catch (e) {
        yield iter.end();
        throw e;
      }
    }

    if (value)
      values.push(value);
  }

  return values;
});

/**
 * Dump database (for debugging).
 * @method
 * @returns {Promise} - Returns Object.
 */

LowlevelUp.prototype.dump = co(function* dump() {
  var records = {};
  var i, items, item, key, value;

  items = yield this.range({
    gte: new Buffer([0x00]),
    lte: new Buffer([0xff])
  });

  for (i = 0; i < items.length; i++) {
    item = items[i];
    key = item.key.toString('hex');
    value = item.value.toString('hex');
    records[key] = value;
  }

  return records;
});

/**
 * Write and assert a version number for the database.
 * @method
 * @param {Number} version
 * @returns {Promise}
 */

LowlevelUp.prototype.checkVersion = co(function* checkVersion(key, version) {
  var data = yield this.get(key);

  if (!data) {
    data = new Buffer(4);
    data.writeUInt32LE(version, 0, true);
    yield this.put(key, data);
    return;
  }

  data = data.readUInt32LE(0, true);

  if (data !== version)
    throw new Error(VERSION_ERROR);
});

/**
 * Clone the database.
 * @method
 * @param {String} path
 * @returns {Promise}
 */

LowlevelUp.prototype.clone = co(function* clone(path) {
  var options = util.merge({}, this.options);
  var opt = { keys: true, values: true };
  var hwm = 256 << 20;
  var total = 0;
  var tmp, batch, iter, item;

  if (!this.loaded)
    throw new Error('Database is closed.');

  options.createIfMissing = true;
  options.errorIfExists = true;

  tmp = new LowlevelUp(path, options);

  yield tmp.open();

  batch = tmp.batch();
  iter = this.iterator(opt);

  for (;;) {
    item = yield iter.next();

    if (!item)
      break;

    batch.put(item.key, item.value);
    total += item.value.length;

    if (total >= hwm) {
      total = 0;
      try {
        yield batch.write();
      } catch (e) {
        yield iter.end();
        yield tmp.close();
        throw e;
      }
      batch = tmp.batch();
    }
  }

  try {
    yield batch.write();
  } finally {
    yield tmp.close();
  }
});

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

Batch.prototype.put = function(key, value) {
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
  var self = this;
  return new Promise(function(resolve, reject) {
    self.batch.write(co.wrap(resolve, reject));
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
  this.iter = db.db.iterator(options);
}

/**
 * Seek to the next key.
 * @returns {Promise}
 */

Iterator.prototype.next = function() {
  var self = this;
  return new Promise(function(resolve, reject) {
    self.iter.next(function(err, key, value) {
      if (err) {
        self.iter.end(function() {
          reject(err);
        });
        return;
      }

      if (key === undefined && value === undefined) {
        self.iter.end(co.wrap(resolve, reject));
        return;
      }

      resolve(new KeyValue(key, value));
    });
  });
};

/**
 * Seek to an arbitrary key.
 * @param {String|Buffer}
 */

Iterator.prototype.seek = function seek(key) {
  this.iter.seek(key);
};

/**
 * End the iterator.
 * @returns {Promise}
 */

Iterator.prototype.end = function end() {
  var self = this;
  return new Promise(function(resolve, reject) {
    self.iter.end(co.wrap(resolve, reject));
  });
};

/*
 * Helpers
 */

function KeyValue(key, value) {
  this.key = key;
  this.value = value;
}

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
