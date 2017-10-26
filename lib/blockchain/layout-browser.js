/*!
 * layout-browser.js - chaindb layout for browser.
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');

const layout = {
  binary: false,
  R: 'R',
  O: 'O',
  V: 'v',
  e: function e(hash) {
    return 'e' + hex(hash);
  },
  h: function h(hash) {
    return 'h' + hex(hash);
  },
  H: function H(height) {
    return 'H' + hex32(height);
  },
  n: function n(hash) {
    return 'n' + hex(hash);
  },
  p: function p(hash) {
    return 'p' + hex(hash);
  },
  b: function b(hash) {
    return 'b' + hex(hash);
  },
  t: function t(hash) {
    return 't' + hex(hash);
  },
  c: function c(hash, index) {
    return 'c' + hex(hash) + hex32(index);
  },
  u: function u(hash) {
    return 'u' + hex(hash);
  },
  v: function v(bit, hash) {
    return 'v' + hex8(bit) + hex(hash);
  },
  vv: function vv(key) {
    assert(typeof key === 'string');
    assert(key.length === 36);
    return [parseInt(key.slice(1, 3), 16), key.slice(3, 35)];
  },
  T: function T(addr, hash) {
    addr = hex(addr);

    if (addr.length === 64)
      return 'W' + addr + hex(hash);

    assert(addr.length === 40);
    return 'T' + addr + hex(hash);
  },
  C: function C(addr, hash, index) {
    addr = hex(addr);

    if (addr.length === 64)
      return 'X' + addr + hex(hash) + hex32(index);

    assert(addr.length === 40);
    return 'C' + addr + hex(hash) + hex32(index);
  },
  pp: function pp(key) {
    assert(typeof key === 'string');
    assert(key.length === 65);
    return key.slice(1, 65);
  },
  Cc: function Cc(key) {
    assert(typeof key === 'string');

    let hash, index;
    if (key.length === 137) {
      hash = key.slice(65, 129);
      index = parseInt(key.slice(129), 16);
    } else if (key.length === 113) {
      hash = key.slice(41, 105);
      index = parseInt(key.slice(105), 16);
    } else {
      assert(false);
    }

    return [hash, index];
  },
  Tt: function Tt(key) {
    assert(typeof key === 'string');

    if (key.length === 129)
      return key.slice(64);

    assert(key.length === 105);
    return key.slice(41);
  }
};

/*
 * Helpers
 */

function hex(hash) {
  if (Buffer.isBuffer(hash))
    hash = hash.toString('hex');
  assert(typeof hash === 'string');
  return hash;
}

function hex8(num) {
  assert(typeof num === 'number');
  assert(num >= 0 && num <= 255);

  if (num <= 0x0f)
    return '0' + num.toString(16);

  if (num <= 0xff)
    return num.toString(16);

  throw new Error('Number too big.');
}

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

/*
 * Expose
 */

module.exports = layout;
