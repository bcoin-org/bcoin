/*!
 * common.js - common functions for descriptor
 * Copyright (c) 2023, the bcoin developers (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');
const common = exports;

/**
 * Types of script expressions in descriptors
 * @see https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md#reference
 * @const {Object}
 */

common.types = {
  PK: 'pk',
  PKH: 'pkh',
  WPKH: 'wpkh',
  SH: 'sh',
  WSH: 'wsh',
  COMBO: 'combo',
  ADDR: 'addr',
  MULTI: 'multi',
  SORTEDMULTI: 'sortedmulti',
  RAW: 'raw'
};

/**
 * Types of script expressions by value in descriptors
 * @const {Object}
 */

common.typesByVal = {
  pk: 'PK',
  pkh: 'PKH',
  wpkh: 'WPKH',
  sh: 'SH',
  wsh: 'WSH',
  combo: 'COMBO',
  addr: 'ADDR',
  multi: 'MULTI',
  sortedmulti: 'SORTEDMULTI',
  raw: 'RAW'
};

/**
 * parse script context for descriptor
 * @const {Object}
 */

common.scriptContext = {
  TOP: 'TOP',
  P2SH: 'P2SH',
  P2WPKH: 'P2WPKH',
  P2WSH: 'P2WSH'
};

/**
 * Allowed characters in descriptor expressions for checksum to work.
 * @see https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki#character-set
 * @const {String}
 */

const INPUT_CHARSET = '0123456789()[],\'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ' +
                       '&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#"\\ ';

 /**
 * Checksum character set.
 * The checksum itself uses the same character set as bech32
 * @const {String}
 */

const CHECKSUM_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

/**
 * Test whether this descriptor string starts with particular script type
 * ('pk', 'pkh', 'wpkh' etc.)
 * @param {String} scriptType script type
 * @param {String} desc descriptor string
 * @returns {Boolean}
 */

common.isType = function isType(scriptType, desc) {
  assert(typeof scriptType === 'string');
  assert(typeof desc === 'string');

  /**
   * First check whether descriptor string length is atleast greater than
   * scriptType length + 2 (for brackets)
   * Then check character at scriptType length is '(' and last character is ')'
   * in descriptor string
   * Then check whether descriptor string starts with scriptType
   */

  return desc.length >= scriptType.length + 2
         && desc[scriptType.length] === '('
         && desc[desc.length - 1] === ')'
         && scriptType === desc.substring(0, scriptType.length);
};

/**
 * Test whether a string is hex string.
 * @param {String} str
 * @returns {Boolean}
 */

common.isHex = function isHex(str) {
  assert(typeof str === 'string');
  return (str.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(str)) ;
};

/**
 * Get the top level script expression of the descriptor.
 * @param {String} desc descriptor string
 * @returns {String} script expression of descriptor
 */

common.getType = function getType(desc) {
  const scriptType = desc.substring(0, desc.indexOf('('));

  if (common.typesByVal[scriptType]) {
    return scriptType;
  }

  return null;
};

/**
 * Strip script expression string from descriptor
 * @param {String} desc descriptor string
 * @returns {String} descriptor string without script expression
 */

common.strip = function strip(desc) {
  return desc.substring(desc.indexOf('(') + 1, desc.length - 1);
};

/**
 * Internal function that computes the descriptor checksum
 * @see https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki#checksum
 * @see https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki
 * @param {BigInt} c
 * @param {BigInt} val
 * @returns {BigInt} checksum
 */

function polyMod(c, val) {
  const c0 = c >> 35n;
  c = ((c & 0x7ffffffffn) << 5n) ^ val;

  if (c0 & 1n)
    c ^= 0xf5dee51989n;
  if (c0 & 2n)
    c ^= 0xa9fdca3312n;
  if (c0 & 4n)
    c ^= 0x1bab10e32dn;
  if (c0 & 8n)
    c ^= 0x3706b1677an;
  if (c0 & 16n)
    c ^= 0x644d626ffdn;

  return c;
}

/**
 * Get the checksum of a descriptor string
 * @param {String} desc
 * @returns {String} checksum string
 */

common.createChecksum = function createChecksum(desc) {
  let c = 1n;
  let cls = 0n;
  let clscount = 0n;

  for (let i = 0; i < desc.length; ++i) {
    const ch = desc[i];
    const pos = BigInt(INPUT_CHARSET.indexOf(ch));

    assert(pos !== -1n, `Invalid character ${ch} at position ${i}`);

    c = polyMod(c, pos & 31n);
    cls = cls * 3n + (pos >> 5n);

    if (++clscount === 3n) {
      c = polyMod(c, cls);
      cls = 0n;
      clscount = 0n;
    }
  }

  if (clscount > 0) {
    c = polyMod(c, cls);
  }

  for (let j = 0; j < 8; ++j) {
    c = polyMod(c, 0n);
  }

  c ^= 1n;

  let checksum = '';
  for (let k = 0n; k < 8n; ++k) {
    const v = (c >> (5n * (7n - k))) & 31n;
    checksum += CHECKSUM_CHARSET[v];
  }

  return checksum;
};

/**
 * Test whether the descriptor has valid checksum (if present).
 * If requireChecksum is true, will error if no checksum is present.
 * @param {String} desc
 * @param {Boolean?} requireChecksum
 * @returns {String} descriptor string without checksum part
 * @throws {AssertionError}
 */

common.checkChecksum = function checkChecksum(desc, requireChecksum = false) {
  const checkSplit = desc.split('#');
  assert(checkSplit.length <= 2, 'Multiple # symbols');

  if (checkSplit.length === 1) {
    assert(!requireChecksum, 'Missing checksum');
  }

  if (checkSplit.length === 2) {
    assert(
      checkSplit[1].length === 8,
      `Expected 8 characters checksum, not ${checkSplit[1].length} characters`
    );
  }

  const checksum = common.createChecksum(checkSplit[0]);

  if (checkSplit.length === 2) {
    assert(
      checksum === checkSplit[1],
      `Expected checksum ${checksum}, found ${checkSplit[1]}`
    );
  }

  return checkSplit[0];
};

/**
 * Get descriptor string with checksum appended.
 * @param {String} desc
 * @returns {String} descriptor string with checksum appended
 */

common.addChecksum = function addChecksum(desc) {
  const split = desc.split('#');
  const checksum = common.createChecksum(split[0]);
  return split[0] + '#' + checksum;
};
