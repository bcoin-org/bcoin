/*!
 * layout.js - data layout for wallets
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const layouts = exports;

const Key = require('bdb/lib/key');

/*
 * Wallet Database Layout:
 *  p[addr-hash] -> wallet ids
 *  P[wid][addr-hash] -> path data
 *  r[wid][index][hash] -> path account index
 *  w[wid] -> wallet
 *  l[id] -> wid
 *  a[wid][index] -> account
 *  i[wid][name] -> account index
 *  n[wid][index] -> account name
 *  t[wid]* -> txdb
 *  R -> chain sync state
 *  h[height] -> recent block hash
 *  b[height] -> block->wid map
 *  o[hash][index] -> outpoint->wid map
 *  T[hash] -> tx->wid map
 */

const p = new Key('p', ['hash']);
const P = new Key('P', ['uint32', 'hash']);
const r = new Key('r', ['uint32', 'uint32', 'hash']);
const w = new Key('w', ['uint32']);
const l = new Key('l', ['ascii']);
const a = new Key('a', ['uint32', 'uint32']);
const i = new Key('i', ['uint32', 'ascii']);
const n = new Key('n', ['uint32', 'uint32']);
const R = new Key('R');
const h = new Key('h', ['uint32']);
const b = new Key('b', ['uint32']);
const o = new Key('o', ['hash256', 'uint32']);
const T = new Key('T', ['hash256']);

// Pp
// rr
layouts.walletdb = {
  binary: true,
  p: p.build.bind(p),
  pp: p.parse.bind(p),
  P: P.build.bind(P),
  Pp: P.parse.bind(P),
  r: r.build.bind(r),
  rr: r.parse.bind(r),
  w: w.build.bind(w),
  ww: w.parse.bind(w),
  l: l.build.bind(l),
  ll: l.parse.bind(l),
  a: a.build.bind(a),
  i: i.build.bind(i),
  ii: i.parse.bind(i),
  n: n.build.bind(n),
  R: R.build.bind(R),
  h: h.build.bind(h),
  b: b.build.bind(b),
  bb: b.parse.bind(b),
  o: o.build.bind(o),
  oo: o.parse.bind(o),
  T: T.build.bind(T),
  Tt: T.parse.bind(T)
};

/*
 * TXDB Database Layout:
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
 *   r[hash] -> dummy (replace by fee chain)
 */

{
const prefix = new Key('t', ['uint32']);
const R = new Key('R');
const r = new Key('r', ['uint32']);
const t = new Key('t', ['hash256']);
const c = new Key('c', ['hash256', 'uint32']);
const d = new Key('d', ['hash256', 'uint32']);
const s = new Key('s', ['hash256', 'uint32']);
const p = new Key('p', ['hash256']);
const m = new Key('m', ['uint32', 'hash256']);
const h = new Key('h', ['uint32', 'hash256']);
const T = new Key('T', ['uint32', 'hash256']);
const P = new Key('P', ['uint32', 'hash256']);
const M = new Key('M', ['uint32', 'uint32', 'hash256']);
const H = new Key('H', ['uint32', 'uint32', 'hash256']);
const C = new Key('C', ['uint32', 'hash256', 'uint32']);
const b = new Key('b', ['uint32']);

layouts.txdb = {
  binary: true,
  prefix: prefix.build.bind(prefix),
  R: R.build.bind(R),
  r: r.build.bind(r),
  rr: r.parse.bind(r),
  t: t.build.bind(t),
  tt: t.parse.bind(t),
  c: c.build.bind(c),
  cc: c.parse.bind(c),
  d: d.build.bind(d),
  dd: d.parse.bind(d),
  s: s.build.bind(s),
  ss: s.parse.bind(s),
  p: p.build.bind(p),
  pp: p.parse.bind(p),
  m: m.build.bind(m),
  mm: m.parse.bind(m),
  h: h.build.bind(h),
  hh: h.parse.bind(h),
  T: T.build.bind(T),
  Tt: T.parse.bind(T),
  P: P.build.bind(P),
  Pp: P.parse.bind(P),
  M: M.build.bind(M),
  Mm: M.parse.bind(M),
  H: H.build.bind(H),
  Hh: H.parse.bind(H),
  C: C.build.bind(C),
  Cc: C.parse.bind(C),
  b: b.build.bind(b),
  bb: b.parse.bind(b)
};
}
