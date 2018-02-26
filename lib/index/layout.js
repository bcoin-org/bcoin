/*!
 * layout.js - indexdb layout for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const bdb = require('bdb');

/*
 * Index Database Layout:
 *  V -> db version
 *  O -> flags
 *  h[height] -> recent block hash
 *  R -> chain sync state
 *  g[hash] -> basic compact filter
 *  G[hash] -> basic compact filter header
 *  x[hash] -> extended compact filter
 *  X[hash] -> extended compact filter header
 *  t[hash] -> extended tx
 *  T[addr-hash][hash] -> dummy (tx by address)
 *  C[addr-hash][hash][index] -> dummy (coin by address)
 */

const layout = {
  V: bdb.key('V'),
  O: bdb.key('O'),
  h: bdb.key('h', ['uint32']),
  R: bdb.key('R'),
  g: bdb.key('g', ['hash256']),
  G: bdb.key('G', ['hash256']),
  x: bdb.key('x', ['hash256']),
  X: bdb.key('X', ['hash256']),
  t: bdb.key('t', ['hash256']),
  T: bdb.key('T', ['hash', 'hash256']),
  C: bdb.key('C', ['hash', 'hash256', 'uint32'])
};

/*
 * Expose
 */

module.exports = layout;
