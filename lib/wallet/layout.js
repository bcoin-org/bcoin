/*!
 * layout.js - data layout for wallets
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const layouts = exports;

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
 */

layouts.walletdb = {
  binary: true,
  p: function p(hash) {
    let key = Buffer.allocUnsafe(1 + (hash.length / 2));
    key[0] = 0x70;
    key.write(hash, 1, 'hex');
    return key;
  },
  pp: function pp(key) {
    return key.toString('hex', 1);
  },
  P: function P(wid, hash) {
    let key = Buffer.allocUnsafe(1 + 4 + (hash.length / 2));
    key[0] = 0x50;
    key.writeUInt32BE(wid, 1, true);
    key.write(hash, 5, 'hex');
    return key;
  },
  Pp: function Pp(key) {
    return key.toString('hex', 5);
  },
  r: function r(wid, index, hash) {
    let key = Buffer.allocUnsafe(1 + 4 + 4 + (hash.length / 2));
    key[0] = 0x72;
    key.writeUInt32BE(wid, 1, true);
    key.writeUInt32BE(index, 5, true);
    key.write(hash, 9, 'hex');
    return key;
  },
  rr: function rr(key) {
    return key.toString('hex', 9);
  },
  w: function w(wid) {
    let key = Buffer.allocUnsafe(5);
    key[0] = 0x77;
    key.writeUInt32BE(wid, 1, true);
    return key;
  },
  ww: function ww(key) {
    return key.readUInt32BE(1, true);
  },
  l: function l(id) {
    let len = Buffer.byteLength(id, 'ascii');
    let key = Buffer.allocUnsafe(1 + len);
    key[0] = 0x6c;
    if (len > 0)
      key.write(id, 1, 'ascii');
    return key;
  },
  ll: function ll(key) {
    return key.toString('ascii', 1);
  },
  a: function a(wid, index) {
    let key = Buffer.allocUnsafe(9);
    key[0] = 0x61;
    key.writeUInt32BE(wid, 1, true);
    key.writeUInt32BE(index, 5, true);
    return key;
  },
  i: function i(wid, name) {
    let len = Buffer.byteLength(name, 'ascii');
    let key = Buffer.allocUnsafe(5 + len);
    key[0] = 0x69;
    key.writeUInt32BE(wid, 1, true);
    if (len > 0)
      key.write(name, 5, 'ascii');
    return key;
  },
  ii: function ii(key) {
    return [key.readUInt32BE(1, true), key.toString('ascii', 5)];
  },
  n: function n(wid, index) {
    let key = Buffer.allocUnsafe(9);
    key[0] = 0x6e;
    key.writeUInt32BE(wid, 1, true);
    key.writeUInt32BE(index, 5, true);
    return key;
  },
  R: Buffer.from([0x52]),
  h: function h(height) {
    let key = Buffer.allocUnsafe(5);
    key[0] = 0x68;
    key.writeUInt32BE(height, 1, true);
    return key;
  },
  b: function b(height) {
    let key = Buffer.allocUnsafe(5);
    key[0] = 0x62;
    key.writeUInt32BE(height, 1, true);
    return key;
  },
  bb: function bb(key) {
    return key.readUInt32BE(1, true);
  },
  o: function o(hash, index) {
    let key = Buffer.allocUnsafe(37);
    key[0] = 0x6f;
    key.write(hash, 1, 'hex');
    key.writeUInt32BE(index, 33, true);
    return key;
  },
  oo: function oo(key) {
    return [key.toString('hex', 1, 33), key.readUInt32BE(33, true)];
  }
};

/*
 * TXDB Database Layout:
 *   t[hash] -> extended tx
 *   c[hash][index] -> coin
 *   d[hash][index] -> undo coin
 *   s[hash][index] -> spent by hash
 *   o[hash][index] -> orphan inputs
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

layouts.txdb = {
  binary: true,
  prefix: function prefix(wid, key) {
    let out = Buffer.allocUnsafe(5 + key.length);
    out[0] = 0x74;
    out.writeUInt32BE(wid, 1);
    key.copy(out, 5);
    return out;
  },
  pre: function prefix(key) {
    return key.readUInt32BE(1, true);
  },
  R: Buffer.from([0x52]),
  hi: function hi(ch, hash, index) {
    let key = Buffer.allocUnsafe(37);
    key[0] = ch;
    key.write(hash, 1, 'hex');
    key.writeUInt32BE(index, 33, true);
    return key;
  },
  hii: function hii(key) {
    key = key.slice(6);
    return [key.toString('hex', 0, 32), key.readUInt32BE(32, true)];
  },
  ih: function ih(ch, index, hash) {
    let key = Buffer.allocUnsafe(37);
    key[0] = ch;
    key.writeUInt32BE(index, 1, true);
    key.write(hash, 5, 'hex');
    return key;
  },
  ihh: function ihh(key) {
    key = key.slice(6);
    return [key.readUInt32BE(0, true), key.toString('hex', 4, 36)];
  },
  iih: function iih(ch, index, num, hash) {
    let key = Buffer.allocUnsafe(41);
    key[0] = ch;
    key.writeUInt32BE(index, 1, true);
    key.writeUInt32BE(num, 5, true);
    key.write(hash, 9, 'hex');
    return key;
  },
  iihh: function iihh(key) {
    key = key.slice(6);
    return [
      key.readUInt32BE(0, true),
      key.readUInt32BE(4, true),
      key.toString('hex', 8, 40)
    ];
  },
  ihi: function ihi(ch, index, hash, num) {
    let key = Buffer.allocUnsafe(41);
    key[0] = ch;
    key.writeUInt32BE(index, 1, true);
    key.write(hash, 5, 'hex');
    key.writeUInt32BE(num, 37, true);
    return key;
  },
  ihii: function ihii(key) {
    key = key.slice(6);
    return [
      key.readUInt32BE(0, true),
      key.toString('hex', 4, 36),
      key.readUInt32BE(36, true)
    ];
  },
  ha: function ha(ch, hash) {
    let key = Buffer.allocUnsafe(33);
    key[0] = ch;
    key.write(hash, 1, 'hex');
    return key;
  },
  haa: function haa(key) {
    key = key.slice(6);
    return key.toString('hex', 0);
  },
  t: function t(hash) {
    return this.ha(0x74, hash);
  },
  tt: function tt(key) {
    return this.haa(key);
  },
  c: function c(hash, index) {
    return this.hi(0x63, hash, index);
  },
  cc: function cc(key) {
    return this.hii(key);
  },
  d: function d(hash, index) {
    return this.hi(0x64, hash, index);
  },
  dd: function dd(key) {
    return this.hii(key);
  },
  s: function s(hash, index) {
    return this.hi(0x73, hash, index);
  },
  ss: function ss(key) {
    return this.hii(key);
  },
  p: function p(hash) {
    return this.ha(0x70, hash);
  },
  pp: function pp(key) {
    return this.haa(key);
  },
  m: function m(time, hash) {
    return this.ih(0x6d, time, hash);
  },
  mm: function mm(key) {
    return this.ihh(key);
  },
  h: function h(height, hash) {
    return this.ih(0x68, height, hash);
  },
  hh: function hh(key) {
    return this.ihh(key);
  },
  T: function T(account, hash) {
    return this.ih(0x54, account, hash);
  },
  Tt: function Tt(key) {
    return this.ihh(key);
  },
  P: function P(account, hash) {
    return this.ih(0x50, account, hash);
  },
  Pp: function Pp(key) {
    return this.ihh(key);
  },
  M: function M(account, time, hash) {
    return this.iih(0x4d, account, time, hash);
  },
  Mm: function Mm(key) {
    return this.iihh(key);
  },
  H: function H(account, height, hash) {
    return this.iih(0x48, account, height, hash);
  },
  Hh: function Hh(key) {
    return this.iihh(key);
  },
  C: function C(account, hash, index) {
    return this.ihi(0x43, account, hash, index);
  },
  Cc: function Cc(key) {
    return this.ihii(key);
  },
  r: function r(hash) {
    return this.ha(0x72, hash);
  },
  b: function b(height) {
    let key = Buffer.allocUnsafe(5);
    key[0] = 0x62;
    key.writeUInt32BE(height, 1, true);
    return key;
  },
  bb: function bb(key) {
    key = key.slice(6);
    return key.readUInt32BE(0, true);
  }
};
