/*!
 * layout.js - data layout for wallets
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const bdb = require('bdb');

/*
 * Wallet Database Layout:
 *  V -> db version
 *  O -> flags
 *  R -> chain sync state
 *  D -> wallet id depth
 *  p[addr-hash] -> wallet ids
 *  P[wid][addr-hash] -> path data
 *  r[wid][index][hash] -> path account index
 *  w[wid] -> wallet
 *  W[wid] -> wallet id
 *  l[id] -> wid
 *  a[wid][index] -> account
 *  i[wid][name] -> account index
 *  n[wid][index] -> account name
 *  h[height] -> recent block hash
 *  b[height] -> block->wid map
 *  o[hash][index] -> outpoint->wid map
 *  T[hash] -> tx->wid map
 *  t[wid]* -> txdb
 */

exports.wdb = {
  V: bdb.key('V'),
  O: bdb.key('O'),
  R: bdb.key('R'),
  D: bdb.key('D'),
  p: bdb.key('p', ['hash']),
  P: bdb.key('P', ['uint32', 'hash']),
  r: bdb.key('r', ['uint32', 'uint32', 'hash']),
  w: bdb.key('w', ['uint32']),
  W: bdb.key('W', ['uint32']),
  l: bdb.key('l', ['ascii']),
  a: bdb.key('a', ['uint32', 'uint32']),
  i: bdb.key('i', ['uint32', 'ascii']),
  n: bdb.key('n', ['uint32', 'uint32']),
  h: bdb.key('h', ['uint32']),
  b: bdb.key('b', ['uint32']),
  o: bdb.key('o', ['hash256', 'uint32']),
  T: bdb.key('T', ['hash256']),
  t: bdb.key('t', ['uint32'])
};

/*
 * TXDB Database Layout:
 *   R -> wallet balance
 *   r[account] -> account balance
 *   t[hash] -> extended tx
 *   c[hash][index] -> coin
 *   d[hash][index] -> undo coin
 *   s[hash][index] -> spent by hash
 *   p[hash] -> dummy (pending flag)
 *   m[time][hash] -> dummy (tx by time)
 *   h[height][hash] -> dummy (tx by height)
 *   T[account][hash] -> dummy (tx by account)
 *   P[account][hash] -> dummy (pending tx by account)
 *   M[account][time][hash] -> dummy (tx by time + account)
 *   H[account][height][hash] -> dummy (tx by height + account)
 *   C[account][hash][index] -> dummy (coin by account)
 *   b[height] -> block record
 */

exports.txdb = {
  prefix: bdb.key('t', ['uint32']),
  R: bdb.key('R'),
  r: bdb.key('r', ['uint32']),
  t: bdb.key('t', ['hash256']),
  c: bdb.key('c', ['hash256', 'uint32']),
  d: bdb.key('d', ['hash256', 'uint32']),
  s: bdb.key('s', ['hash256', 'uint32']),
  p: bdb.key('p', ['hash256']),
  m: bdb.key('m', ['uint32', 'hash256']),
  h: bdb.key('h', ['uint32', 'hash256']),
  T: bdb.key('T', ['uint32', 'hash256']),
  P: bdb.key('P', ['uint32', 'hash256']),
  M: bdb.key('M', ['uint32', 'uint32', 'hash256']),
  H: bdb.key('H', ['uint32', 'uint32', 'hash256']),
  C: bdb.key('C', ['uint32', 'hash256', 'uint32']),
  b: bdb.key('b', ['uint32'])
};
