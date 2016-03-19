/**
 * ldb.js - global ldb tracker
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bcoin = require('../bcoin');
var network = bcoin.protocol.network;
var db = {};

module.exports = function ldb(name, options) {
  var levelup = require('levelup');
  var file = bcoin.prefix + '/' + name + '-' + network.type + '.db';
  var backend = process.env.BCOIN_DB;

  bcoin.ensurePrefix();

  if (!db[file]) {
    if (bcoin.isBrowser) {
      backend = 'level-js';
    } else {
      if (!backend || backend === 'rocksdb')
        backend = 'rocksdown';
      else if (backend === 'leveldb')
        backend = 'leveldown';
      else if (backend === 'lmdb')
        backend = 'lmdb';
      else if (backend === 'tree')
        backend = 'tree';
      else
        assert(false, 'Bad DB.');
    }

    db[file] = new levelup(file, {
      keyEncoding: 'ascii',
      valueEncoding: 'binary',
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

      db: require(backend)
    });
  }

  return db[file];
};
