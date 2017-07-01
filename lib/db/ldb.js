/**
 * ldb.js - database backend for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const LowlevelUp = require('./lowlevelup');
const backends = require('./backends');

/**
 * Create a database.
 * @alias module:db.LDB
 * @param {Object} options
 * @returns {LowlevelUp}
 */

function LDB(options) {
  let result = LDB.getBackend(options);
  let backend = result.backend;
  let location = result.location;

  return new LowlevelUp(backend, location, options);
}

/**
 * Get database name and extension based on options.
 * @param {String} db
 * @returns {Object}
 */

LDB.getName = function getName(db) {
  let name, ext;

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
      name = 'memory';
      ext = 'mem';
      break;
    default:
      name = db;
      ext = 'db';
      break;
  }

  return [name, ext];
};

/**
 * Get target backend and location.
 * @param {Object} options
 * @returns {Object}
 */

LDB.getBackend = function getBackend(options) {
  let [name, ext] = LDB.getName(options.db);
  let backend = backends.get(name);
  let location = options.location;

  if (typeof location !== 'string') {
    assert(name === 'memory', 'Location required.');
    location = 'memory';
  }

  return {
    backend: backend,
    location: `${location}.${ext}`
  };
};

/*
 * Expose
 */

module.exports = LDB;
