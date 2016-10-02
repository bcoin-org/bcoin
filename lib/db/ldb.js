/**
 * global ldb tracker
 * @module ldb
 * @license
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var LowlevelUp = require('./lowlevelup');
var utils = require('../utils/utils');
var assert = require('assert');

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
  var target = ldb.getTarget(options);

  if (target.backend !== 'rbt')
    utils.mkdir(target.location, true);

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

ldb.getBackend = function getBackend(db) {
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

ldb.getTarget = function getTarget(options) {
  var backend = ldb.getBackend(options.db);
  var location = options.location;
  var db;

  if (backend.name === 'rbt')
    db = require('./rbt');
  else if (utils.isBrowser)
    db = require('./level');
  else
    db = require(backend.name);

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

module.exports = ldb;
