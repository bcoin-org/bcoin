/*!
 * layout.js - blockchain data layout for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const bdb = require('bdb');

/*
 * Database Layout:
 *   V -> db version
 *   O -> chain options
 *   R -> tip hash
 *   D -> versionbits deployments
 *   e[hash] -> entry
 *   h[hash] -> height
 *   H[height] -> hash
 *   n[hash] -> next hash
 *   p[hash] -> tip index
 *   b[hash] -> block
 *   t[hash] -> extended tx
 *   c[hash] -> coins
 *   u[hash] -> undo coins
 *   v[bit][hash] -> versionbits state
 *   T[addr-hash][hash] -> dummy (tx by address)
 *   C[addr-hash][hash][index] -> dummy (coin by address)
 */

const layout = {
  V: bdb.key('V'),
  O: bdb.key('O'),
  R: bdb.key('R'),
  D: bdb.key('D'),
  e: bdb.key('e', ['bhash256']),
  h: bdb.key('h', ['bhash256']),
  H: bdb.key('H', ['uint32']),
  n: bdb.key('n', ['bhash256']),
  p: bdb.key('p', ['bhash256']),
  b: bdb.key('b', ['bhash256']),
  t: bdb.key('t', ['bhash256']),
  c: bdb.key('c', ['bhash256', 'uint32']),
  u: bdb.key('u', ['bhash256']),
  v: bdb.key('v', ['uint8', 'bhash256']),
  T: bdb.key('T', ['bhash', 'bhash256']),
  C: bdb.key('C', ['bhash', 'bhash256', 'uint32'])
};

/*
 * Expose
 */

module.exports = layout;
