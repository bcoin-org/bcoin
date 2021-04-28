/*!
 * util.js - utils for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');
const util = exports;

/**
 * Test whether a number is Number,
 * finite, and below MAX_SAFE_INTEGER.
 * @param {Number?} value
 * @returns {Boolean}
 */

util.isNumber = function isNumber(value) {
  return typeof value === 'number'
    && isFinite(value)
    && value >= -Number.MAX_SAFE_INTEGER
    && value <= Number.MAX_SAFE_INTEGER;
};

/**
 * Test whether an object is an int.
 * @param {Number?} value
 * @returns {Boolean}
 */

util.isInt = function isInt(value) {
  return Number.isSafeInteger(value);
};

/**
 * Test whether an object is a uint.
 * @param {Number?} value
 * @returns {Boolean}
 */

util.isUint = function isUint(value) {
  return util.isInt(value) && value >= 0;
};

/**
 * Test whether a number is a float.
 * @param {Number?} value
 * @returns {Boolean}
 */

util.isFloat = function isFloat(value) {
  return typeof value === 'number' && isFinite(value);
};

/**
 * Test whether a number is a positive float.
 * @param {Number?} value
 * @returns {Boolean}
 */

util.isUfloat = function isUfloat(value) {
  return util.isFloat(value) && value >= 0;
};

/**
 * Test whether an object is an int8.
 * @param {Number?} value
 * @returns {Boolean}
 */

util.isI8 = function isI8(value) {
  return (value | 0) === value && value >= -0x80 && value <= 0x7f;
};

/**
 * Test whether an object is an int16.
 * @param {Number?} value
 * @returns {Boolean}
 */

util.isI16 = function isI16(value) {
  return (value | 0) === value && value >= -0x8000 && value <= 0x7fff;
};

/**
 * Test whether an object is an int32.
 * @param {Number?} value
 * @returns {Boolean}
 */

util.isI32 = function isI32(value) {
  return (value | 0) === value;
};

/**
 * Test whether an object is a int53.
 * @param {Number?} value
 * @returns {Boolean}
 */

util.isI64 = function isI64(value) {
  return util.isInt(value);
};

/**
 * Test whether an object is a uint8.
 * @param {Number?} value
 * @returns {Boolean}
 */

util.isU8 = function isU8(value) {
  return (value & 0xff) === value;
};

/**
 * Test whether an object is a uint16.
 * @param {Number?} value
 * @returns {Boolean}
 */

util.isU16 = function isU16(value) {
  return (value & 0xffff) === value;
};

/**
 * Test whether an object is a uint32.
 * @param {Number?} value
 * @returns {Boolean}
 */

util.isU32 = function isU32(value) {
  return (value >>> 0) === value;
};

/**
 * Test whether an object is a uint53.
 * @param {Number?} value
 * @returns {Boolean}
 */

util.isU64 = function isU64(value) {
  return util.isUint(value);
};

/**
 * Test whether a string is a plain
 * ascii string (no control characters).
 * @param {String} str
 * @returns {Boolean}
 */

util.isAscii = function isAscii(str) {
  return typeof str === 'string' && /^[\t\n\r -~]*$/.test(str);
};

/**
 * Test whether a string is base58 (note that you
 * may get a false positive on a hex string).
 * @param {String?} str
 * @returns {Boolean}
 */

util.isBase58 = function isBase58(str) {
  return typeof str === 'string' && /^[1-9A-Za-z]+$/.test(str);
};

/**
 * Test whether a string is bech32 (note that
 * this doesn't guarantee address is bech32).
 * @param {String?} str
 * @returns {Boolean}
 */

util.isBech32 = function isBech32(str) {
  if (typeof str !== 'string')
    return false;

  if (str.toUpperCase() !== str && str.toLowerCase() !== str)
    return false;

  if (str.length < 8 || str.length > 90)
    return false;

  // it's unlikely any network will have hrp other than a-z symbols.
  return /^[a-z]{1,3}1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]+$/i.test(str);
};

/**
 * Test whether a string is hex (length must be even).
 * Note that this _could_ await a false positive on
 * base58 strings.
 * @param {String?} str
 * @returns {Boolean}
 */

util.isHex = function isHex(str) {
  if (typeof str !== 'string')
    return false;
  return str.length % 2 === 0 && /^[0-9A-Fa-f]+$/.test(str);
};

/**
 * Test whether an object is a 160 bit hash (hex string).
 * @param {String?} hash
 * @returns {Boolean}
 */

util.isHex160 = function isHex160(hash) {
  if (typeof hash !== 'string')
    return false;
  return hash.length === 40 && util.isHex(hash);
};

/**
 * Test whether an object is a 256 bit hash (hex string).
 * @param {String?} hash
 * @returns {Boolean}
 */

util.isHex256 = function isHex256(hash) {
  if (typeof hash !== 'string')
    return false;
  return hash.length === 64 && util.isHex(hash);
};

/**
 * Test whether the result of a positive
 * addition would be below MAX_SAFE_INTEGER.
 * @param {Number} value
 * @returns {Boolean}
 */

util.isSafeAddition = function isSafeAddition(a, b) {
  // We only work on positive numbers.
  assert(a >= 0);
  assert(b >= 0);

  // Fast case.
  if (a <= 0xfffffffffffff && b <= 0xfffffffffffff)
    return true;

  // Do a 64 bit addition and check the top 11 bits.
  let ahi = (a * (1 / 0x100000000)) | 0;
  const alo = a | 0;

  let bhi = (b * (1 / 0x100000000)) | 0;
  const blo = b | 0;

  // Credit to @indutny for this method.
  const lo = (alo + blo) | 0;

  const s = lo >> 31;
  const as = alo >> 31;
  const bs = blo >> 31;

  const c = ((as & bs) | (~s & (as ^ bs))) & 1;

  let hi = (((ahi + bhi) | 0) + c) | 0;

  hi >>>= 0;
  ahi >>>= 0;
  bhi >>>= 0;

  // Overflow?
  if (hi < ahi || hi < bhi)
    return false;

  return (hi & 0xffe00000) === 0;
};
