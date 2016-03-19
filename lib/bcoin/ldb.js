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
  var levelup = require('levelup');
  var file = bcoin.prefix + '/' + name + '-' + network.type + '.db';
  var backend = process.env.BCOIN_DB;
  var promise;

  bcoin.ensurePrefix();

  if (!db[file]) {
    if (bcoin.isBrowser) {
      backend = require('level-js');
    } else {
      if (!backend || backend === 'rocksdb')
        backend = 'rocksdown';
      else if (backend === 'leveldb')
        backend = 'leveldown';
      else if (backend === 'lmdb')
        backend = 'lmdb';

      backend = require(backend);
    }

    /*
    db[file] = new levelup(file, {
      keyEncoding: 'ascii',
      valueEncoding: 'binary',
      createIfMissing: true,
      errorIfExists: false,
      compression: options.compression !== false,
      cacheSize: options.cacheSize || (8 << 20),
      writeBufferSize: options.writeBufferSize || (4 << 20),
      memtableSize: 10 << 20,
      maxOpenFiles: options.maxOpenFiles || 8192,

      // For LMDB if we decide to use it:
      sync: options.sync || false,
      mapSize: options.mapSize || 150 * (1024 << 20),
      writeMap: options.writeMap || false,

      db: backend
    });
    */
    db[file] = new DBWrapper(backend, file, {
      keyEncoding: 'ascii',
      valueEncoding: 'binary',
      createIfMissing: true,
      errorIfExists: false,
      compression: options.compression !== false,
      cacheSize: options.cacheSize || (8 << 20),
      writeBufferSize: options.writeBufferSize || (4 << 20),
      memtableSize: 10 << 20,
      maxOpenFiles: options.maxOpenFiles || 8192,

      // For LMDB if we decide to use it:
      sync: options.sync || false,
      mapSize: options.mapSize || 150 * (1024 << 20),
      writeMap: options.writeMap || false,

      db: backend
    });
  }

  return db[file];
};

/**
 * DBWrapper
 */

function DBWrapper(backend, file, options) {
  var self = this;

  if (!(this instanceof DBWrapper))
    return new DBWrapper(backend, file, options);

  EventEmitter.call(this);

  this.loaded = false;

  this.backend = new backend(file);
  this.db = this.backend;

  this.backend.open(options, function(err) {
    if (err)
      return self.emit('error', err);

    self.emit('load');
    self.loaded = true;
  });
}

utils.inherits(DBWrapper, EventEmitter);

DBWrapper.prototype.open = function open(callback) {
  if (this.loaded)
    return utils.nextTick(callback);

  this.once('load', callback);
};

DBWrapper.prototype.get = function get(key, options, callback) {
  if (typeof options === 'function') {
    callback = options;
    options = {};
  }
  return this.backend.get(key, options, function(err, result) {
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

DBWrapper.prototype.close = function close(callback) {
  return this.backend.close(callback);
};

DBWrapper.prototype.put = function put(key, value, options, callback) {
  return this.backend.put(key, value, options, callback);
};

DBWrapper.prototype.del = function del(key, options, callback) {
  return this.backend.del(key, options, callback);
};

DBWrapper.prototype.batch = function batch(ops, options, callback) {
  if (!ops)
    return this.backend.batch();
  return this.backend.batch(ops, options, callback);
};

DBWrapper.prototype.iterator = function batch(ops, options, callback) {
  return this.backend.iterator(options);
};

DBWrapper.prototype.getProperty = function getProperty(name) {
  if (this.backend.getProperty)
    return this.backend.getProperty(name);

  if (this.backend.db && this.backend.db.getProperty)
    return this.backend.db.getProperty(name);

  return null;
};

DBWrapper.prototype.approximateSize = function approximateSize(start, end, callback) {
  return this.backend.approximateSize(start, end, callback);
};
