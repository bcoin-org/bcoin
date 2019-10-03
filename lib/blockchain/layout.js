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
 *   i[hash] -> dummy (invalid flag)
 *   h[hash] -> height
 *   H[height] -> hash
 *   n[hash] -> next hash
 *   r[hash] -> next hash references
 *   s[hash] -> skip ancestor hash
 *   p[hash] -> tip index (deprecated)
 *   w[bn][hash] -> tip chainwork index
 *   b[hash] -> block (deprecated)
 *   t[hash] -> extended tx (deprecated)
 *   c[hash] -> coins
 *   u[hash] -> undo coins (deprecated)
 *   v[bit][hash] -> versionbits state
 *   T[addr-hash][hash] -> dummy (tx by address) (deprecated)
 *   C[addr-hash][hash][index] -> dummy (coin by address) (deprecated)
 */

const layout = {
  V: bdb.key('V'),
  O: bdb.key('O'),
  R: bdb.key('R'),
  D: bdb.key('D'),
  e: bdb.key('e', ['hash256']),
  i: bdb.key('i', ['hash256']),
  h: bdb.key('h', ['hash256']),
  H: bdb.key('H', ['uint32']),
  n: bdb.key('n', ['hash256']),
  r: bdb.key('r', ['hash256']),
  s: bdb.key('s', ['hash256']),
  p: bdb.key('p', ['hash256']),
  w: bdb.key('w', ['hex', 'hash256']),
  b: bdb.key('b', ['hash256']),
  t: bdb.key('t', ['hash256']),
  c: bdb.key('c', ['hash256', 'uint32']),
  u: bdb.key('u', ['hash256']),
  v: bdb.key('v', ['uint8', 'hash256']),
  T: bdb.key('T', ['hash', 'hash256']),
  C: bdb.key('C', ['hash', 'hash256', 'uint32'])
};

/*
 * Expose
 */

module.exports = layout;
