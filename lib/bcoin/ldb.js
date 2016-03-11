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
  var cacheSize = options.cacheSize || 8 * 1024 * 1024;
  var writeBufferSize = options.writeBufferSize || (cacheSize / 2 | 0);

  bcoin.ensurePrefix();

  if (!db[file]) {
    db[file] = new levelup(file, {
      keyEncoding: 'ascii',
      valueEncoding: 'binary',
      createIfMissing: true,
      errorIfExists: false,
      compression: options.compression !== false,
      cacheSize: cacheSize,
      writeBufferSize: writeBufferSize,
      maxOpenFiles: options.maxOpenFiles || 8192,
      db: bcoin.isBrowser
        ? require('level-js')
        : require('level' + 'down')
    });
  }

  return db[file];
};
