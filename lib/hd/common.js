/*!
 * common.js - common functions for hd
 * Copyright (c) 2015-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const LRU = require('../utils/lru');
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
 * Parse a derivation path and return an array of indexes.
 * @see https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
 * @param {String} path
 * @param {Boolean} hard
 * @returns {Number[]}
 */

common.parsePath = function parsePath(path, hard) {
  assert(typeof path === 'string');
  assert(typeof hard === 'boolean');

  const parts = path.split('/');
  const root = parts.shift();

  if (root !== 'm'
      && root !== 'M'
      && root !== 'm\''
      && root !== 'M\'') {
    throw new Error('Bad path root.');
  }

  const result = [];

  for (let part of parts) {
    const hardened = part[part.length - 1] === '\'';

    if (hardened)
      part = part.slice(0, -1);

    if (!/^\d+$/.test(part))
      throw new Error('Non-number path index.');

    let index = parseInt(part, 10);

    if ((index >>> 0) !== index)
      throw new Error('Index out of range.');

    if (hardened) {
      index |= common.HARDENED;
      index >>>= 0;
    }

    if (!hard && (index & common.HARDENED))
      throw new Error('Cannot derive hardened.');

    result.push(index);
  }

  return result;
};

/**
 * Test whether the key is a master key.
 * @param {HDPrivateKey|HDPublicKey} key
 * @returns {Boolean}
 */

common.isMaster = function isMaster(key) {
  return key.depth === 0
    && key.childIndex === 0
    && key.parentFingerPrint.readUInt32LE(0, true) === 0;
};

/**
 * Test whether the key is (most likely) a BIP44 account key.
 * @param {HDPrivateKey|HDPublicKey} key
 * @param {Number?} account
 * @returns {Boolean}
 */

common.isBIP44 = function isBIP44(key, account) {
  if (account != null) {
    const index = (common.HARDENED | account) >>> 0;
    if (key.childIndex !== index)
      return false;
  }
  return key.depth === 3 && (key.childIndex & common.HARDENED) !== 0;
};

/**
 * Test whether the key is a BIP45 purpose key.
 * @param {HDPrivateKey|HDPublicKey} key
 * @returns {Boolean}
 */

common.isBIP45 = function isBIP45(key) {
  return key.depth === 1 && (key.childIndex & ~common.HARDENED) === 45;
};
