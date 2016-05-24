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
 * @param {String} options.name - Database name.
 * @param {String} options.location - Database location (overrides `name`).
 * @returns {LowlevelUp}
 */

function ldb(options) {
  var file = ldb.getLocation(options);

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

      db: ldb.getBackend(options.db)
    });
  }

  return db[file];
}

/**
 * Get database name and extension based on options.
 * @param {String} db
 * @returns {Object}
 */

ldb.getName = function getName(db) {
  var ext;

  if (!db)
    db = bcoin.db || 'leveldb';

  if (db === 'leveldb')
    name = 'leveldown';
  else if (db === 'rocksdb')
    name = 'rocksdown';
  else if (db === 'lmdb')
    name = 'lmdb';
  else if (db === 'memory')
    name = 'bst';
  else
    name = db;

  switch (name) {
    case 'leveldown':
      ext = 'ldb';
      break;
    case 'rocksdown':
      ext = 'rdb';
      break;
    case 'lmdb':
      ext = 'lmdb';
      break;
    case 'bst':
      ext = 'mem';
      break;
    default:
      ext = 'db';
      break;
  }

  return { name: name, ext: ext };
};

/**
 * Get database location based on options.
 * @param {Object} options
 * @returns {String} Path.
 */

ldb.getLocation = function getLocation(options) {
  var backend = ldb.getName(options.db);

  if (options.location)
    return options.location;

  return bcoin.prefix + '/' + options.name + '.' + backend.ext;
};

/**
 * Require database backend module.
 * @param {String} db
 * @returns {Object} Module.
 */

ldb.getBackend = function getBackend(db) {
  var backend = ldb.getName(db);

  if (backend.name === 'bst')
    return require('./bst');

  if (bcoin.isBrowser)
    return require('level-js');

  bcoin.ensurePrefix();

  return require(backend.name);
};

/**
 * Destroy a database.
 * @param {Object} options
 * @param {Function} callback
 */

ldb.destroy = function destroy(options, callback) {
  var file = ldb.getLocation(options);
  var backend = ldb.getBackend(options.db);

  if (!backend.destroy)
    return utils.nextTick(callback);

  backend.destroy(file, callback);
};

/**
 * Repair a database.
 * @param {Object} options
 * @param {Function} callback
 */

ldb.repair = function repair(options, callback) {
  var file = ldb.getLocation(options);
  var backend = ldb.getBackend(options.db);

  if (!backend.repair)
    return utils.asyncify(callback)(new Error('Cannot repair.'));

  backend.repair(file, callback);
};

/*
 * Expose
 */

module.exports = ldb;
