/*!
 * blockstore/layout.js - file blockstore data layout for bcoin
 * Copyright (c) 2019, Braydon Fuller (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const bdb = require('bdb');

/*
 * Database Layout:
 *   V -> db version
 *   F[type] -> last file record by type
 *   f[type][fileno] -> file record by type and file number
 *   b[type][hash] -> block record by type and block hash
 */

const layout = {
  V: bdb.key('V'),
  F: bdb.key('F', ['uint32']),
  f: bdb.key('f', ['uint32', 'uint32']),
  b: bdb.key('b', ['uint32', 'hash256'])
};

/*
 * Expose
 */

module.exports = layout;
