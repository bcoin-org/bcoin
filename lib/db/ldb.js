/**
 * ldb.js - database backend for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var LowlevelUp = require('./lowlevelup');
var util = require('../utils/util');
var backends = require('./backends');

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

function LDB(options) {
  var target = LDB.getTarget(options);

  if (target.backend !== 'rbt')
    util.mkdir(target.location, true);

  return new LowlevelUp(target.location, {
    // Generic
    createIfMissing: options.createIfMissing !== false,
    errorIfExists: options.errorIfExists === true,

    // LevelDB
    compression: options.compression !== false,
    cacheSize: options.cacheSize || (8 << 20),
    writeBufferSize: options.writeBufferSize || (4 << 20),
    maxOpenFiles: options.maxOpenFiles || 64,
    paranoidChecks: false,
    memory: false,

    // LMDB
    sync: options.sync || false,
    mapSize: options.mapSize || 256 * (1024 << 20),
    writeMap: options.writeMap || false,
    noSubdir: options.noSubdir !== false,

    // Browser
    bufferKeys: options.bufferKeys,

    db: target.db
  });
}

/**
 * Get database name and extension based on options.
 * @param {String} db
 * @returns {Object}
 */

LDB.getBackend = function getBackend(db) {
  var name, ext;

  if (!db)
    db = 'memory';

  switch (db) {
    case 'ldb':
    case 'leveldb':
    case 'leveldown':
      name = 'leveldown';
      ext = 'ldb';
      break;
    case 'rdb':
    case 'rocksdb':
    case 'rocksdown':
      name = 'rocksdown';
      ext = 'rdb';
      break;
    case 'mdb':
    case 'lmdb':
      name = 'lmdb';
      ext = 'mdb';
      break;
    case 'mem':
    case 'memory':
    case 'rbt':
      name = 'rbt';
      ext = 'mem';
      break;
    default:
      name = db;
      ext = 'db';
      break;
  }

  return { name: name, ext: ext };
};

/**
 * Get target backend and location.
 * @param {Object} options
 * @returns {Object}
 */

LDB.getTarget = function getTarget(options) {
  var backend = LDB.getBackend(options.db);
  var location = options.location;
  var db = backends.get(backend.name);

  if (typeof location !== 'string') {
    assert(backend.name === 'rbt', 'Location required.');
    location = 'rbt';
  }

  return {
    db: db,
    backend: backend.name,
    location: location + '.' + backend.ext
  };
};

/*
 * Expose
 */

module.exports = LDB;
