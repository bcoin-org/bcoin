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
 *  g[monotonic-time] -> block hash
 *  G[block-hash] -> monotonic-time
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
  g: bdb.key('g', ['uint32']),
  G: bdb.key('G', ['hash256']),
  b: bdb.key('b', ['uint32']),
  o: bdb.key('o', ['hash256', 'uint32']),
  T: bdb.key('T', ['hash256']),
  t: bdb.key('t', ['uint32'])
};

/*
 * TXDB Database Layout:
 *   Balance
 *   -------
 *   R -> wallet balance
 *   r[account] -> account balance
 *
 *   Transactions
 *   ------------
 *   t[hash] -> extended tx
 *   T[account][hash] -> dummy (tx by account)

 *   Coins
 *   -----
 *   c[hash][index] -> coin
 *   C[account][hash][index] -> dummy (coin by account)
 *   d[hash][index] -> undo coin
 *   s[hash][index] -> spent by hash
 *
 *   Confirmed
 *   ---------
 *   g[monotonic-time][hash] -> dummy (tx by monotonic time)
 *   G[account][monotonic-time][hash] -> dummy (tx by monotonic time + account)
 *   z[count] -> dummy (tx by count)
 *   Z[account][count]-> dummy (tx by count + account)
 *   y[hash] -> count (count for tx)
 *   Y[account][hash] -> count (account count for tx)
 *   h[height][hash] -> dummy (tx by height)
 *   H[account][height][hash] -> dummy (tx by height + account)
 *   b[height] -> block record
 *
 *   Unconfirmed
 *   -----------
 *   w[unconfirmed-time][hash] -> dummy (tx by time)
 *   W[account][unconfirmed-time][hash] -> dummy (tx by time + account)
 *   e[hash] -> unconfirmed-time (unconfirmed time for tx)
 *   u[unconfirmed-count] -> dummy (tx by unconfirmed count)
 *   U[account][unconfirmed-count] -> dummy (tx by unconfirmed count + account)
 *   v[hash] -> unconfirmed count (unconfirmed count for tx)
 *   V[account][hash] -> unconfirmed count (unconfirmed count for tx + account)
 *   p[hash] -> dummy (pending flag)
 *   P[account][hash] -> dummy (pending tx by account)
 */

exports.txdb = {
  prefix: bdb.key('t', ['uint32']),

  // Balance
  R: bdb.key('R'),
  r: bdb.key('r', ['uint32']),

  // Transactions
  t: bdb.key('t', ['hash256']),
  T: bdb.key('T', ['uint32', 'hash256']),

  // Coins
  c: bdb.key('c', ['hash256', 'uint32']),
  C: bdb.key('C', ['uint32', 'hash256', 'uint32']),
  d: bdb.key('d', ['hash256', 'uint32']),
  s: bdb.key('s', ['hash256', 'uint32']),

  // Confirmed
  g: bdb.key('g', ['uint32', 'hash256']),
  G: bdb.key('G', ['uint32', 'uint32', 'hash256']),
  z: bdb.key('z', ['uint32']),
  Z: bdb.key('Z', ['uint32', 'uint32']),
  y: bdb.key('y', ['hash256']),
  Y: bdb.key('Y', ['uint32', 'hash256']),
  h: bdb.key('h', ['uint32', 'hash256']),
  H: bdb.key('H', ['uint32', 'uint32', 'hash256']),
  b: bdb.key('b', ['uint32']),

  // Unconfirmed
  w: bdb.key('w', ['uint32', 'hash256']),
  W: bdb.key('W', ['uint32', 'uint32', 'hash256']),
  e: bdb.key('e', ['hash256']),
  u: bdb.key('u', ['uint32']),
  U: bdb.key('U', ['uint32', 'uint32']),
  v: bdb.key('v', ['hash256']),
  V: bdb.key('V', ['uint32', 'hash256']),
  p: bdb.key('p', ['hash256']),
  P: bdb.key('P', ['uint32', 'hash256'])
};
