/*!
 * layout.js - blockchain data layout for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const Key = require('bdb/lib/key');

/*
 * Database Layout:
 *   R -> tip hash
 *   O -> chain options
 *   e[hash] -> entry
 *   h[hash] -> height
 *   H[height] -> hash
 *   n[hash] -> next hash
 *   p[hash] -> tip index
 *   b[hash] -> block
 *   t[hash] -> extended tx
 *   c[hash] -> coins
 *   u[hash] -> undo coins
 *   v -> versionbits deployments
 *   v[bit][hash] -> versionbits state
 *   T[addr-hash][hash] -> dummy (tx by address)
 *   C[addr-hash][hash][index] -> dummy (coin by address)
 *   W+T[witaddr-hash][hash] -> dummy (tx by address)
 *   W+C[witaddr-hash][hash][index] -> dummy (coin by address)
 */

const R = new Key('R');
const O = new Key('O');
const V = new Key('v');
const e = new Key('e', ['hash256']);
const h = new Key('h', ['hash256']);
const H = new Key('H', ['uint32']);
const n = new Key('n', ['hash256']);
const p = new Key('p', ['hash256']);
const b = new Key('b', ['hash256']);
const t = new Key('t', ['hash256']);
const c = new Key('c', ['hash256', 'uint32']);
const u = new Key('u', ['hash256']);
const v = new Key('v', ['uint8', 'hash256']);
const T160 = new Key('T', ['hash160', 'hash256']);
const T256 = new Key(0xab, ['hash256', 'hash256']);
const C160 = new Key('C', ['hash160', 'hash256', 'uint32']);
const C256 = new Key(0x9a, ['hash256', 'hash256', 'uint32']);

const layout = {
  binary: true,
  R: R.build.bind(R),
  O: O.build.bind(O),
  V: V.build.bind(V),
  e: e.build.bind(e),
  h: h.build.bind(h),
  H: H.build.bind(H),
  n: n.build.bind(n),
  p: p.build.bind(p),
  pp: p.parse.bind(p),
  b: b.build.bind(b),
  t: t.build.bind(t),
  c: c.build.bind(c),
  u: u.build.bind(u),
  v: v.build.bind(v),
  vv: v.parse.bind(v),
  T: function T(addr, hash) {
    let len = addr ? addr.length : 0;
    if (typeof addr === 'string')
      len >>>= 1;
    if (len === 32)
      return T256.build(addr, hash);
    return T160.build(addr, hash);
  },
  Tt: function Tt(key) {
    if (key && key[0] === 0xab)
      return T256.parse(key);
    return T160.parse(key);
  },
  C: function C(addr, hash, index) {
    let len = addr ? addr.length : 0;
    if (typeof addr === 'string')
      len >>>= 1;
    if (len === 32)
      return C256.build(addr, hash, index);
    return C160.build(addr, hash, index);
  },
  Cc: function Cc(key) {
    if (key && key[0] === 0x9a)
      return C256.parse(key);
    return C160.parse(key);
  }
};

/*
 * Expose
 */

module.exports = layout;
