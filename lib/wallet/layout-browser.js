/*!
 * layout-browser.js - walletdb and txdb layout for browser.
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const layouts = exports;

layouts.walletdb = {
  binary: false,
  p: function p(hash) {
    assert(typeof hash === 'string');
    return 'p' + hash;
  },
  pp: function pp(key) {
    assert(typeof key === 'string');
    return key.slice(1);
  },
  P: function P(wid, hash) {
    assert(typeof hash === 'string');
    return 'p' + hex32(wid) + hash;
  },
  Pp: function Pp(key) {
    assert(typeof key === 'string');
    return key.slice(11);
  },
  r: function r(wid, index, hash) {
    assert(typeof hash === 'string');
    return 'r' + hex32(wid) + hex32(index) + hash;
  },
  rr: function rr(key) {
    assert(typeof key === 'string');
    return key.slice(21);
  },
  w: function w(wid) {
    return 'w' + hex32(wid);
  },
  ww: function ww(key) {
    assert(typeof key === 'string');
    return parseInt(key.slice(1), 16);
  },
  l: function l(id) {
    assert(typeof id === 'string');
    return 'l' + id;
  },
  ll: function ll(key) {
    assert(typeof key === 'string');
    return key.slice(1);
  },
  a: function a(wid, index) {
    return 'a' + hex32(wid) + hex32(index);
  },
  i: function i(wid, name) {
    assert(typeof name === 'string');
    return 'i' + hex32(wid) + name;
  },
  ii: function ii(key) {
    assert(typeof key === 'string');
    return [parseInt(key.slice(1, 9), 16), key.slice(9)];
  },
  n: function n(wid, index) {
    return 'n' + hex32(wid) + hex32(index);
  },
  R: 'R',
  h: function h(height) {
    return 'h' + hex32(height);
  },
  b: function b(height) {
    return 'b' + hex32(height);
  },
  bb: function bb(key) {
    assert(typeof key === 'string');
    return parseInt(key.slice(1), 16);
  },
  o: function o(hash, index) {
    assert(typeof hash === 'string');
    return 'o' + hash + hex32(index);
  },
  oo: function oo(key) {
    return [key.slice(1, 65), parseInt(key.slice(65), 16)];
  },
  T: function T(hash) {
    assert(typeof hash === 'string');
    return 'T' + hash;
  },
  Tt: function Tt(key) {
    return [key.slice(1, 65)];
  }
};

layouts.txdb = {
  binary: false,
  prefix: function prefix(wid) {
    return 't' + hex32(wid);
  },
  R: 'R',
  r: function r(acct) {
    assert(typeof acct === 'number');
    return 'r' + hex32(acct);
  },
  rr: function rr(key) {
    assert(typeof key === 'string');
    return parseInt(key.slice(1), 16);
  },
  hi: function hi(ch, hash, index) {
    assert(typeof hash === 'string');
    return ch + hash + hex32(index);
  },
  hii: function hii(key) {
    assert(typeof key === 'string');
    return [key.slice(1, 65), parseInt(key.slice(65), 16)];
  },
  ih: function ih(ch, index, hash) {
    assert(typeof hash === 'string');
    return ch + hex32(index) + hash;
  },
  ihh: function ihh(key) {
    assert(typeof key === 'string');
    return [parseInt(key.slice(1, 9), 16), key.slice(9)];
  },
  iih: function iih(ch, index, num, hash) {
    assert(typeof hash === 'string');
    return ch + hex32(index) + hex32(num) + hash;
  },
  iihh: function iihh(key) {
    assert(typeof key === 'string');
    return [
      parseInt(key.slice(1, 9), 16),
      parseInt(key.slice(9, 17), 16),
      key.slice(17)
    ];
  },
  ihi: function ihi(ch, index, hash, num) {
    assert(typeof hash === 'string');
    return ch + hex32(index) + hash + hex32(num);
  },
  ihii: function ihii(key) {
    assert(typeof key === 'string');
    return [
      parseInt(key.slice(1, 9), 16),
      key.slice(9, 73),
      parseInt(key.slice(73), 16)
    ];
  },
  ha: function ha(ch, hash) {
    assert(typeof hash === 'string');
    return ch + hash;
  },
  haa: function haa(key) {
    assert(typeof key === 'string');
    return key.slice(1);
  },
  t: function t(hash) {
    return this.ha('t', hash);
  },
  tt: function tt(key) {
    return this.haa(key);
  },
  c: function c(hash, index) {
    return this.hi('c', hash, index);
  },
  cc: function cc(key) {
    return this.hii(key);
  },
  d: function d(hash, index) {
    return this.hi('d', hash, index);
  },
  dd: function dd(key) {
    return this.hii(key);
  },
  s: function s(hash, index) {
    return this.hi('s', hash, index);
  },
  ss: function ss(key) {
    return this.hii(key);
  },
  S: function S(hash, index) {
    return this.hi('S', hash, index);
  },
  Ss: function Ss(key) {
    return this.hii(key);
  },
  p: function p(hash) {
    return this.ha('p', hash);
  },
  pp: function pp(key) {
    return this.haa(key);
  },
  m: function m(time, hash) {
    return this.ih('m', time, hash);
  },
  mm: function mm(key) {
    return this.ihh(key);
  },
  h: function h(height, hash) {
    return this.ih('h', height, hash);
  },
  hh: function hh(key) {
    return this.ihh(key);
  },
  T: function T(account, hash) {
    return this.ih('T', account, hash);
  },
  Tt: function Tt(key) {
    return this.ihh(key);
  },
  P: function P(account, hash) {
    return this.ih('P', account, hash);
  },
  Pp: function Pp(key) {
    return this.ihh(key);
  },
  M: function M(account, time, hash) {
    return this.iih('M', account, time, hash);
  },
  Mm: function Mm(key) {
    return this.iihh(key);
  },
  H: function H(account, height, hash) {
    return this.iih('H', account, height, hash);
  },
  Hh: function Hh(key) {
    return this.iihh(key);
  },
  C: function C(account, hash, index) {
    return this.ihi('C', account, hash, index);
  },
  Cc: function Cc(key) {
    return this.ihii(key);
  },
  b: function b(height) {
    return 'b' + hex32(height);
  },
  bb: function bb(key) {
    assert(typeof key === 'string');
    return parseInt(key.slice(1), 16);
  }
};

function hex32(num) {
  assert(typeof num === 'number');
  assert(num >= 0);

  num = num.toString(16);

  switch (num.length) {
    case 1:
      return '0000000' + num;
    case 2:
      return '000000' + num;
    case 3:
      return '00000' + num;
    case 4:
      return '0000' + num;
    case 5:
      return '000' + num;
    case 6:
      return '00' + num;
    case 7:
      return '0' + num;
    case 8:
      return num;
  }

  throw new Error('Number too big.');
}
