/**
 * backends.js - database backends for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

exports.get = function get(name) {
  try {
    switch (name) {
      case 'leveldown':
        return require('leveldown');
      case 'rocksdown':
        return require('rocksdown');
      case 'lmdb':
        return require('lmdb');
      case 'memory':
        return require('./memdb');
      default:
        throw new Error(`Database backend "${name}" not found.`);
    }
  } catch (e) {
    if (e.code === 'MODULE_NOT_FOUND')
      throw new Error(`Database backend "${name}" not found.`);
    throw e;
  }
};
