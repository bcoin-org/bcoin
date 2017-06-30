/*!
 * layout-browser.js - chaindb layout for browser.
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

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
  c: function c(hash) {
    return 'c' + hex(hash);
  },
  u: function u(hash) {
    return 'u' + hex(hash);
  },
  v: function v(bit, hash) {
    return 'v' + pad8(bit) + hex(hash);
  },
  vv: function vv(key) {
    return [+key.slice(1, 4), key.slice(4, 36)];
  },
  T: function T(address, hash) {
    address = hex(address);

    if (address.length === 64)
      return 'W' + address + hex(hash);

    return 'T' + address + hex(hash);
  },
  C: function C(address, hash, index) {
    address = hex(address);

    if (address.length === 64)
      return 'X' + address + hex(hash) + pad32(index);

    return 'C' + address + hex(hash) + pad32(index);
  },
  pp: function aa(key) {
    return key.slice(1, 65);
  },
  Cc: function Cc(key) {
    let hash, index;

    if (key.length === 139) {
      hash = key.slice(65, 129);
      index = +key.slice(129);
    } else {
      hash = key.slice(41, 105);
      index = +key.slice(105);
    }

    return [hash, index];
  },
  Tt: function Tt(key) {
    return key.length === 129
      ? key.slice(64)
      : key.slice(41);
  }
};

/*
 * Helpers
 */

function hex(hash) {
  if (typeof hash !== 'string')
    hash = hash.toString('hex');
  return hash;
}

/*
 * Expose
 */

module.exports = layout;
