/**
 * global ldb tracker
 * @module ldb
 * @license
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var bcoin = require('./env');
var LowlevelUp = require('./lowlevelup');
var utils = bcoin.utils;
var assert = utils.assert;
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
  options = ldb.parseOptions(options);

  if (!db[options.location]) {
    if (options.backend !== 'bst' && !bcoin.isBrowser)
      bcoin.mkdir(options.location, true);

    db[options.location] = new LowlevelUp(options.location, {
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

      db: options.db
    });
  }

  return db[options.location];
}

/**
 * Get database name and extension based on options.
 * @param {String} db
 * @returns {Object}
 */

ldb.getBackend = function getBackend(db) {
  var name, ext;

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
 * Parse options.
 * @param {Object} options
 * @returns {Object}
 */

ldb.parseOptions = function parseOptions(options) {
  var network = bcoin.network.get(options.network);
  var backend = ldb.getBackend(options.db);
  var location = options.location;
  var db;

  if (!location) {
    assert(typeof options.name === 'string', 'Name or location required.');
    location = bcoin.prefix;
    if (network.type !== 'main')
      location += '/' + network.type;
    location += '/' + options.name + '.' + backend.ext;
  }

  if (backend.name === 'bst')
    db = require('./bst');
  else if (bcoin.isBrowser)
    db = require('level-js');
  else
    db = require(backend.name);

  return utils.merge({}, options, {
    backend: backend.name,
    ext: backend.ext,
    location: location,
    db: db
  });
};

/*
 * Expose
 */

module.exports = ldb;
