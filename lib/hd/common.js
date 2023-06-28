/*!
 * common.js - common functions for hd
 * Copyright (c) 2015-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');
const LRU = require('blru');
const common = exports;

/**
 * Index at which hardening begins.
 * @const {Number}
 * @default
 */

common.HARDENED = 0x80000000;

/**
 * Min entropy bits.
 * @const {Number}
 * @default
 */

common.MIN_ENTROPY = 128;

/**
 * Max entropy bits.
 * @const {Number}
 * @default
 */

common.MAX_ENTROPY = 512;

/**
 * LRU cache to avoid deriving keys twice.
 * @type {LRU}
 */

common.cache = new LRU(500);

/**
 * Parse a derivation path.
 * @param {Array} path
 * @param {Boolean} hard
 * @returns {Number[]}
 */

common.parsePathFromArray = function parsePathFromArray(path, hard) {
  assert(Array.isArray(path), 'Path must be an array.');
  assert(typeof hard === 'boolean');

  const result = [];
  for (let i = 0; i < path.length; i++) {
    let part = path[i];

    const last = part[part.length - 1];

    const hardened = last === '\'' || last === 'h';

    if (hardened) {
      part = part.slice(0, -1);
    }

    if (part.length > 10)
      throw new Error('Path index too large.');

    if (!/^\d+$/.test(part))
      throw new Error('Path index is non-numeric.');

    let index = parseInt(part, 10);

    if ((index >>> 0) !== index)
      throw new Error('Path index out of range.');

    if (index > 0x7fffffff) {
      throw new Error(`Key path value ${index} is out of range`);
    }

    if (hardened) {
      index |= common.HARDENED;
      index >>>= 0;
    }

    if (!hard && (index & common.HARDENED))
      throw new Error('Path index cannot be hardened.');

    result.push(index);
  }

  return result;
};

/**
 * Parse a derivation path and return an array of indexes.
 * @see https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
 * @param {String} path
 * @param {Boolean} hard
 * @returns {Number[]}
 */

common.parsePath = function parsePath(path, hard) {
  assert(typeof path === 'string');
  assert(typeof hard === 'boolean');
  assert(path.length >= 1);
  assert(path.length <= 3062);

  let parts = path.split('/');
  const root = parts[0];
  parts = parts.slice(1);

  if (root !== 'm'
      && root !== 'M'
      && root !== 'm\''
      && root !== 'M\'') {
    throw new Error('Invalid path root.');
  }

  return this.parsePathFromArray(parts, hard);
};

/**
 * Format the derivation path (indexes).
 * @param {Array} path
 * @param {String} hardenedMarker `h` or `'`
 * Whether to format path using apostrophes (e.g. `m/44'/0'/0'`)
 * or with h (e.g. `m/44h/0h/0h`).
 * @returns {String}
 */

common.format = function format(path, hardenedMarker) {
  assert(Array.isArray(path));
  assert(typeof hardenedMarker === 'string');
  assert(hardenedMarker === '\'' || hardenedMarker === 'h');

  let res = '';
  for (const p of path) {
    const hardened = p & common.HARDENED ? hardenedMarker : '';
    res += `/${p & 0x7fffffff}${hardened}`;
  }
  return res;
};

/**
 * Test whether the key is a master key.
 * @param {HDPrivateKey|HDPublicKey} key
 * @returns {Boolean}
 */

common.isMaster = function isMaster(key) {
  return key.depth === 0
    && key.childIndex === 0
    && key.parentFingerPrint === 0;
};

/**
 * Test whether the key is (most likely) a BIP44 account key.
 * @param {HDPrivateKey|HDPublicKey} key
 * @param {Number?} account
 * @returns {Boolean}
 */

common.isAccount = function isAccount(key, account) {
  if (account != null) {
    const index = (common.HARDENED | account) >>> 0;
    if (key.childIndex !== index)
      return false;
  }
  return key.depth === 3 && (key.childIndex & common.HARDENED) !== 0;
};

/**
 * A compressed pubkey of all zeroes.
 * @const {Buffer}
 * @default
 */

common.ZERO_KEY = Buffer.alloc(33, 0x00);
