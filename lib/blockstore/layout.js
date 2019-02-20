/*!
 * blockstore/layout.js - file block store data layout for bcoin
 * Copyright (c) 2019, Braydon Fuller (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const bdb = require('bdb');

/*
 * Database Layout:
 *   V -> db version
 *   R -> last file entry
 *   f[uint32] -> file entry
 *   b[hash] -> block entry
 */

const layout = {
  V: bdb.key('V'),
  R: bdb.key('R'),
  f: bdb.key('f', ['uint32']),
  b: bdb.key('b', ['hash256'])
};

/*
 * Expose
 */

module.exports = layout;
