/*!
 * layout-browser.js - chaindb layout for browser.
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const util = require('../utils/util');
const pad8 = util.pad8;
const pad32 = util.pad32;

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
    return 'H' + pad32(height);
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
    return 'c' + hex(hash) + pad32(index);
  },
  u: function u(hash) {
    return 'u' + hex(hash);
  },
  v: function v(bit, hash) {
    return 'v' + pad8(bit) + hex(hash);
  },
  vv: function vv(key) {
    assert(typeof key === 'string');
    assert(key.length === 36);
    return [parseInt(key.slice(1, 4), 10), key.slice(4, 36)];
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
      return 'X' + addr + hex(hash) + pad32(index);

    assert(addr.length === 40);
    return 'C' + addr + hex(hash) + pad32(index);
  },
  pp: function pp(key) {
    assert(typeof key === 'string');
    assert(key.length === 65);
    return key.slice(1, 65);
  },
  Cc: function Cc(key) {
    assert(typeof key === 'string');

    let hash, index;
    if (key.length === 139) {
      hash = key.slice(65, 129);
      index = parseInt(key.slice(129), 10);
    } else if (key.length === 115) {
      hash = key.slice(41, 105);
      index = parseInt(key.slice(105), 10);
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

/*
 * Expose
 */

module.exports = layout;
