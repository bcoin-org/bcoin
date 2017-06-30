/*!
 * common.js - common functions for hd
 * Copyright (c) 2015-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const LRU = require('../utils/lru');
const common = exports;

/**
 * Index at which hardening begins.
 * @const {Number}
 * @default
 */

common.HARDENED = 0x80000000;

/**
 * Max index (u32max + 1).
 * @const {Number}
 * @default
 */

common.MAX_INDEX = 0x100000000;

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
 * Seed salt for key derivation ("Bitcoin seed").
 * @const {Buffer}
 * @default
 */

common.SEED_SALT = Buffer.from('Bitcoin seed', 'ascii');

/**
 * LRU cache to avoid deriving keys twice.
 * @type {LRU}
 */

common.cache = new LRU(500);

/**
 * Parse a derivation path and return an array of indexes.
 * @see https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
 * @param {String} path
 * @param {Number?} max - Max index.
 * @returns {Number[]}
 */

common.parsePath = function parsePath(path, max) {
  let parts = path.split('/');
  let root = parts.shift();
  let result = [];

  if (max == null)
    max = common.MAX_INDEX;

  if (root !== 'm'
      && root !== 'M'
      && root !== 'm\''
      && root !== 'M\'') {
    throw new Error('Bad path root.');
  }

  for (let index of parts) {
    let hardened = index[index.length - 1] === '\'';

    if (hardened)
      index = index.slice(0, -1);

    if (!/^\d+$/.test(index))
      throw new Error('Non-number path index.');

    index = parseInt(index, 10);

    if (hardened)
      index += common.HARDENED;

    if (!(index >= 0 && index < max))
      throw new Error('Index out of range.');

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
 * @param {Number?} accountIndex
 * @returns {Boolean}
 */

common.isAccount44 = function isAccount44(key, accountIndex) {
  if (accountIndex != null) {
    if (key.childIndex !== common.HARDENED + accountIndex)
      return false;
  }
  return key.depth === 3 && key.childIndex >= common.HARDENED;
};

/**
 * Test whether the key is a BIP45 purpose key.
 * @param {HDPrivateKey|HDPublicKey} key
 * @returns {Boolean}
 */

common.isPurpose45 = function isPurpose45(key) {
  return key.depth === 1 && key.childIndex === common.HARDENED + 45;
};
