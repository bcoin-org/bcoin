/*!
 * fixed.js - fixed number parsing
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');

/**
 * Convert int to fixed number string and reduce by a
 * power of ten (uses no floating point arithmetic).
 * @param {Number} num
 * @param {Number} exp - Number of decimal places.
 * @returns {String} Fixed number string.
 */

exports.encode = function encode(num, exp) {
  assert(Number.isSafeInteger(num), 'Invalid integer value.');

  let sign = '';

  if (num < 0) {
    num = -num;
    sign = '-';
  }

  const mult = pow10(exp);

  let lo = num % mult;
  let hi = (num - lo) / mult;

  lo = lo.toString(10);
  hi = hi.toString(10);

  while (lo.length < exp)
    lo = '0' + lo;

  lo = lo.replace(/0+$/, '');

  assert(lo.length <= exp, 'Invalid integer value.');

  if (lo.length === 0)
    lo = '0';

  if (exp === 0)
    return `${sign}${hi}`;

  return `${sign}${hi}.${lo}`;
};

/**
 * Parse a fixed number string and multiply by a
 * power of ten (uses no floating point arithmetic).
 * @param {String} str
 * @param {Number} exp - Number of decimal places.
 * @returns {Number} Integer.
 */

exports.decode = function decode(str, exp) {
  assert(typeof str === 'string');
  assert(str.length <= 32, 'Fixed number string too large.');

  let sign = 1;

  if (str.length > 0 && str[0] === '-') {
    str = str.substring(1);
    sign = -1;
  }

  let hi = str;
  let lo = '0';

  const index = str.indexOf('.');

  if (index !== -1) {
    hi = str.substring(0, index);
    lo = str.substring(index + 1);
  }

  hi = hi.replace(/^0+/, '');
  lo = lo.replace(/0+$/, '');

  assert(hi.length <= 16 - exp,
    'Fixed number string exceeds 2^53-1.');

  assert(lo.length <= exp,
    'Too many decimal places in fixed number string.');

  if (hi.length === 0)
    hi = '0';

  while (lo.length < exp)
    lo += '0';

  if (lo.length === 0)
    lo = '0';

  assert(/^\d+$/.test(hi) && /^\d+$/.test(lo),
    'Non-numeric characters in fixed number string.');

  hi = parseInt(hi, 10);
  lo = parseInt(lo, 10);

  const mult = pow10(exp);
  const maxLo = modSafe(mult);
  const maxHi = divSafe(mult);

  assert(hi < maxHi || (hi === maxHi && lo <= maxLo),
    'Fixed number string exceeds 2^53-1.');

  return sign * (hi * mult + lo);
};

/**
 * Convert int to float and reduce by a power
 * of ten (uses no floating point arithmetic).
 * @param {Number} num
 * @param {Number} exp - Number of decimal places.
 * @returns {Number} Double float.
 */

exports.toFloat = function toFloat(num, exp) {
  return parseFloat(exports.encode(num, exp));
};

/**
 * Parse a double float number and multiply by a
 * power of ten (uses no floating point arithmetic).
 * @param {Number} num
 * @param {Number} exp - Number of decimal places.
 * @returns {Number} Integer.
 */

exports.fromFloat = function fromFloat(num, exp) {
  assert(typeof num === 'number' && isFinite(num));
  assert(Number.isSafeInteger(exp));
  return exports.decode(num.toFixed(exp), exp);
};

/*
 * Helpers
 */

function pow10(exp) {
  switch (exp) {
    case 0:
      return 1;
    case 1:
      return 10;
    case 2:
      return 100;
    case 3:
      return 1000;
    case 4:
      return 10000;
    case 5:
      return 100000;
    case 6:
      return 1000000;
    case 7:
      return 10000000;
    case 8:
      return 100000000;
  }
  throw new Error('Exponent is too large.');
}

function modSafe(mod) {
  switch (mod) {
    case 1:
      return 0;
    case 10:
      return 1;
    case 100:
      return 91;
    case 1000:
      return 991;
    case 10000:
      return 991;
    case 100000:
      return 40991;
    case 1000000:
      return 740991;
    case 10000000:
      return 4740991;
    case 100000000:
      return 54740991;
  }
  throw new Error('Exponent is too large.');
}

function divSafe(div) {
  switch (div) {
    case 1:
      return 9007199254740991;
    case 10:
      return 900719925474099;
    case 100:
      return 90071992547409;
    case 1000:
      return 9007199254740;
    case 10000:
      return 900719925474;
    case 100000:
      return 90071992547;
    case 1000000:
      return 9007199254;
    case 10000000:
      return 900719925;
    case 100000000:
      return 90071992;
  }
  throw new Error('Exponent is too large.');
}
