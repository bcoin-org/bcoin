/**
 * ldb.js - global ldb tracker
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var EventEmitter = require('events').EventEmitter;
var bcoin = require('../bcoin');
var utils = bcoin.utils;
var network = bcoin.protocol.network;
var db = {};

module.exports = function ldb(name, options) {
  var file = bcoin.prefix + '/' + name + '-' + network.type + '.db';
  var backend = typeof options.db === 'string'
    ? options.db
    : process.env.BCOIN_DB;

  if (!db[file]) {
    if (options.db && typeof options.db !== 'string') {
      bcoin.ensurePrefix();
      backend = options.db;
    } else if (bcoin.isBrowser && backend !== 'memdown') {
      backend = require('level-js');
    } else {
      if (!backend || backend === 'leveldb')
        backend = 'leveldown';
      else if (backend === 'rocksdb')
        backend = 'rocksdown';
      else if (backend === 'lmdb')
        backend = 'lmdb';
      else if (backend === 'memory')
        backend = 'memdown';

      if (backend !== 'memdown')
        bcoin.ensurePrefix();

      backend = require(backend);
    }

    if (!options)
      options = {};

    db[file] = new LowlevelUp(file, {
      keyEncoding: 'ascii',
      valueEncoding: 'binary',

      // LevelDB and others
      createIfMissing: true,
      errorIfExists: false,
      compression: options.compression !== false,
      cacheSize: options.cacheSize || (8 << 20),
      writeBufferSize: options.writeBufferSize || (4 << 20),
      maxOpenFiles: options.maxOpenFiles || 8192,

      // For LMDB if we decide to use it:
      sync: options.sync || false,
      mapSize: options.mapSize || 150 * (1024 << 20),
      writeMap: options.writeMap || false,

      // For RocksDB
      // optimizeCompaction: 'level',
      // memtableBudget: 512 << 20,

      db: backend
    });
  }

  return db[file];
};

/**
 * LowlevelUp
 *
 * Extremely low-level version of levelup.
 * The only levelup feature it provides is
 * error-wrapping. It gives a nice recallable
 * `open()` method and event. It assumes ascii
 * keys and binary values.
 *
 * This avoids pulling in extra deps and
 * lowers memory usage.
 */

function LowlevelUp(file, options) {
  var self = this;

  if (!(this instanceof LowlevelUp))
    return new LowlevelUp(file, options);

  EventEmitter.call(this);

  this.loaded = false;

  this.db = new options.db(file);

  // Stay as close to the metal as possible.
  // We want to make calls to C++ directly.
  while (this.db.db && this.db.db.put)
    this.db = this.db.db;

  this.binding = this.db;
  this.hasBinding = false;

  if (this.db.binding) {
    this.binding = this.db.binding;
    this.hasBinding = true;
  }

  this.binding.open(options, function(err) {
    if (err)
      return self.emit('error', err);

    self.loaded = true;
    self.emit('open');
  });
}

utils.inherits(LowlevelUp, EventEmitter);

LowlevelUp.prototype.open = function open(callback) {
  if (this.loaded)
    return utils.nextTick(callback);

  this.once('open', callback);
};

LowlevelUp.prototype.get = function get(key, options, callback) {
  if (typeof options === 'function') {
    callback = options;
    options = {};
  }
  return this.binding.get(key, options, function(err, result) {
    if (err) {
      if (err.notFound || /not\s*found/i.test(err.message)) {
        err.notFound = true;
        err.type = 'NotFoundError';
      }
      return callback(err);
    }
    return callback(null, result);
  });
};

LowlevelUp.prototype.close = function close(callback) {
  return this.binding.close(callback);
};

LowlevelUp.prototype.put = function put(key, value, options, callback) {
  return this.binding.put(key, value, options, callback);
};

LowlevelUp.prototype.del = function del(key, options, callback) {
  return this.binding.del(key, options, callback);
};

LowlevelUp.prototype.batch = function batch(ops, options, callback) {
  if (!ops)
    return this.binding.batch();
  return this.binding.batch(ops, options, callback);
};

LowlevelUp.prototype.iterator = function iterator(options) {
  if (this.hasBinding)
    return new Iterator(this.binding, options);
  return this.db.iterator(options);
};

LowlevelUp.prototype.getProperty = function getProperty(name) {
  if (!this.binding.getProperty)
    return null;

  return this.binding.getProperty(name);
};

LowlevelUp.prototype.approximateSize = function approximateSize(start, end, callback) {
  return this.binding.approximateSize(start, end, callback);
};

function Iterator(binding, options) {
  this.binding = binding.iterator(options);
  this.cache = null;
  this.finished = false;
}

Iterator.prototype.seek = function (key) {
  if (typeof key !== 'string')
    throw new Error('seek requires a string key');
  if (this.cache)
    this.cache.length = 0;
  this.cache = null;
  this.binding.seek(key);
};

Iterator.prototype.next = function next(callback) {
  var self = this;
  var key, value;

  if (this.cache && this.cache.length) {
    key = this.cache.pop();
    value = this.cache.pop();

    utils.nextTick(function() {
      callback(null, key, value);
    });
  } else if (this.finished) {
    utils.nextTick(function() {
      callback();
    });
  } else {
    this.binding.next(function(err, array, finished) {
      if (err)
        return callback(err);

      self.cache = array;
      self.finished = finished;
      self.next(callback);
    });
  }

  return this;
};

Iterator.prototype.end = function end(callback) {
  if (this.cache)
    this.cache.length = 0;
  delete this.cache;
  this.binding.end(callback);
  delete this.binding;
};
