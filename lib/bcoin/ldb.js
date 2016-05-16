/**
 * global ldb tracker
 * @module ldb
 * @license
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

var bcoin = require('./env');
var LowlevelUp = require('./lowlevelup');
var utils = bcoin.utils;
var db = {};

/**
 * @param {Object} options
 * @param {Boolean} options.compression
 * @param {Number} options.cacheSize
 * @param {Number} options.writeBufferSize
 * @param {Number} options.maxOpenFiles
 * @param {Boolean} options.sync
 * @param {Number} options.mapSize
 * @param {Boolean} options.writeMap
 * @param {String} options.db - Database backend (`"leveldb"` by default).
 * @returns {LowlevelUp}
 */

function ldb(options) {
  var file = getLocation(options);

  if (!db[file]) {
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
      filterBits: 0,
      paranoidChecks: false,
      memory: false,

      // For LMDB if we decide to use it:
      sync: options.sync || false,
      mapSize: options.mapSize || 300 * (1024 << 20),
      writeMap: options.writeMap || false,

      db: getBackend(options.db)
    });
  }

  return db[file];
}

function getLocation(options) {
  if (options.location)
    return options.location;

  return bcoin.prefix
    + '/'
    + options.name
    + '-'
    + bcoin.network.get(options.network).type
    + '.db';
}

function getBackend(backend) {
  if (!backend)
    backend = bcoin.db;

  if (!backend || backend === 'leveldb')
    backend = 'leveldown';
  else if (backend === 'rocksdb')
    backend = 'rocksdown';
  else if (backend === 'lmdb')
    backend = 'lmdb';
  else if (backend === 'memory')
    backend = 'bst';

  if (backend === 'bst')
    return require('./bst');

  if (bcoin.isBrowser)
    return require('level-js');

  bcoin.ensurePrefix();

  return require(backend);
}

/**
 * Destroy a database.
 * @param {Object} options
 * @param {Function} callback
 */

function destroy(options, callback) {
  var file = getLocation(options);
  var backend = getBackend(options.db);

  if (!backend.destroy)
    return utils.nextTick(callback);

  backend.destroy(file, callback);
}

/**
 * Repair a database.
 * @param {Object} options
 * @param {Function} callback
 */

function repair(options, callback) {
  var file = getLocation(options);
  var backend = getBackend(options.db);

  if (!backend.repair)
    return utils.asyncify(callback)(new Error('Cannot repair.'));

  backend.repair(file, callback);
}

/*
 * Expose
 */

exports = ldb;

exports.destroy = destroy;
exports.repair = repair;

module.exports = exports;
