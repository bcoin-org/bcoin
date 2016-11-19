/*!
 * amount.js - amount object for bcoin
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var util = require('../utils/util');

/**
 * Amount
 * @constructor
 */

function Amount(value, unit, num) {
  if (!(this instanceof Amount))
    return new Amount(value, unit, num);

  this.value = 0;

  if (value != null)
    this.fromOptions(value, unit, num);
}

Amount.prototype.fromOptions = function fromOptions(value, unit, num) {
  if (typeof unit === 'string')
    return this.from(unit, value, num);

  if (typeof value === 'number')
    return this.fromValue(value);

  return this.fromBTC(value);
};

Amount.prototype.toValue = function toValue() {
  return this.value;
};

Amount.prototype.toSatoshis = function toSatoshis(num) {
  if (num)
    return this.value;

  return this.value.toString(10);
};

Amount.prototype.toBits = function toBits(num) {
  return Amount.serialize(this.value, 2, num);
};

Amount.prototype.toMBTC = function toMBTC(num) {
  return Amount.serialize(this.value, 5, num);
};

Amount.prototype.toBTC = function toBTC(num) {
  return Amount.serialize(this.value, 8, num);
};

Amount.prototype.to = function to(unit, num) {
  switch (unit) {
    case 'sat':
      return this.toSatoshis(num);
    case 'ubtc':
    case 'bits':
      return this.toBits(num);
    case 'mbtc':
      return this.toMBTC(num);
    case 'btc':
      return this.toBTC(num);
  }
  throw new Error('Unknown unit "' + unit + '".');
};

Amount.prototype.toString = function toString() {
  return this.toBTC();
};

Amount.prototype.fromValue = function fromValue(value) {
  assert(util.isInt53(value), 'Value must be an int64.');
  this.value = value;
  return this;
};

Amount.prototype.fromSatoshis = function fromSatoshis(value, num) {
  this.value = Amount.parse(value, 0, num);
  return this;
};

Amount.prototype.fromBits = function fromBits(value, num) {
  this.value = Amount.parse(value, 2, num);
  return this;
};

Amount.prototype.fromMBTC = function fromMBTC(value, num) {
  this.value = Amount.parse(value, 5, num);
  return this;
};

Amount.prototype.fromBTC = function fromBTC(value, num) {
  this.value = Amount.parse(value, 8, num);
  return this;
};

Amount.prototype.from = function from(unit, value, num) {
  switch (unit) {
    case 'sat':
      return this.fromSatoshis(value, num);
    case 'ubtc':
    case 'bits':
      return this.fromBits(value, num);
    case 'mbtc':
      return this.fromMBTC(value, num);
    case 'btc':
      return this.fromBTC(value, num);
  }
  throw new Error('Unknown unit "' + unit + '".');
};

Amount.fromOptions = function fromOptions(value, unit, num) {
  return new Amount().fromOptions(value);
};

Amount.fromValue = function fromValue(value) {
  return new Amount().fromValue(value);
};

Amount.fromSatoshis = function fromSatoshis(value, num) {
  return new Amount().fromSatoshis(value, num);
};

Amount.fromBits = function fromBits(value, num) {
  return new Amount().fromBits(value, num);
};

Amount.fromMBTC = function fromMBTC(value, num) {
  return new Amount().fromMBTC(value, num);
};

Amount.fromBTC = function fromBTC(value, num) {
  return new Amount().fromBTC(value, num);
};

Amount.from = function from(unit, value, num) {
  return new Amount().from(unit, value, num);
};

Amount.prototype.inspect = function inspect() {
  return '<Amount: ' + this.toString() + '>';
};

/**
 * Safely convert satoshis to a BTC string.
 * This function explicitly avoids any
 * floating point arithmetic.
 * @param {Amount} value - Satoshis.
 * @returns {String} BTC string.
 */

Amount.btc = function btc(value, num) {
  if (util.isFloat(value))
    return value;

  return Amount.serialize(value, 8, num);
};

/**
 * Safely convert satoshis to a BTC string.
 * This function explicitly avoids any
 * floating point arithmetic.
 * @param {Amount} value
 * @param {Number} dec - Number of decimals.
 * @param {Boolean} num - Return a number.
 * @returns {String}
 */

Amount.serialize = function serialize(value, dec, num) {
  var negative = false;
  var hi, lo, result;

  assert(util.isInt(value), 'Non-satoshi value for conversion.');

  if (value < 0) {
    value = -value;
    negative = true;
  }

  value = value.toString(10);

  assert(value.length <= 16, 'Number exceeds 2^53-1.');

  while (value.length < dec + 1)
    value = '0' + value;

  hi = value.slice(0, -dec);
  lo = value.slice(-dec);

  lo = lo.replace(/0+$/, '');

  if (lo.length === 0)
    lo += '0';

  result = hi + '.' + lo;

  if (negative)
    result = '-' + result;

  if (num)
    return +result;

  return result;
};

/**
 * Unsafely convert satoshis to a BTC string.
 * @param {Amount} value
 * @param {Number} dec - Number of decimals.
 * @param {Boolean} num - Return a number.
 * @returns {String}
 */

Amount.serializeUnsafe = function serializeUnsafe(value, dec, num) {
  assert(util.isInt(value), 'Non-satoshi value for conversion.');

  value /= pow10(dec);
  value = value.toFixed(dec);

  if (num)
    return +value;

  if (dec !== 0) {
    value = value.replace(/0+$/, '');
    if (value[value.length - 1] === '.')
      value += '0';
  }

  return value;
};

/**
 * Safely convert a BTC string to satoshis.
 * @param {String} value - BTC
 * @returns {Amount} Satoshis.
 * @throws on parse error
 */

Amount.value = function value(value, num) {
  if (util.isInt(value))
    return value;

  return Amount.parse(value, 8, num);
};

/**
 * Safely convert a BTC string to satoshis.
 * This function explicitly avoids any
 * floating point arithmetic. It also does
 * extra validation to ensure the resulting
 * Number will be 53 bits or less.
 * @param {String} value - BTC
 * @param {Number} dec - Number of decimals.
 * @param {Boolean} num - Allow numbers.
 * @returns {Amount} Satoshis.
 * @throws on parse error
 */

Amount.parse = function parse(value, dec, num) {
  var negative = false;
  var mult = pow10(dec);
  var maxLo = modSafe(mult);
  var maxHi = divSafe(mult);
  var parts, hi, lo, result;

  if (num && typeof value === 'number') {
    assert(util.isNumber(value), 'Non-BTC value for conversion.');
    value = value.toString(10);
  }

  assert(util.isFloat(value), 'Non-BTC value for conversion.');

  if (value[0] === '-') {
    negative = true;
    value = value.substring(1);
  }

  parts = value.split('.');

  assert(parts.length <= 2, 'Bad decimal point.');

  hi = parts[0] || '0';
  lo = parts[1] || '0';

  hi = hi.replace(/^0+/, '');
  lo = lo.replace(/0+$/, '');

  assert(hi.length <= 16 - dec, 'Number exceeds 2^53-1.');
  assert(lo.length <= dec, 'Too many decimal places.');

  if (hi.length === 0)
    hi = '0';

  while (lo.length < dec)
    lo += '0';

  hi = parseInt(hi, 10);
  lo = parseInt(lo, 10);

  assert(hi < maxHi || (hi === maxHi && lo <= maxLo),
    'Number exceeds 2^53-1.');

  result = hi * mult + lo;

  if (negative)
    result = -result;

  return result;
};

/**
 * Unsafely convert a BTC string to satoshis.
 * @param {String} value - BTC
 * @param {Number} dec - Number of decimals.
 * @param {Boolean} num - Allow numbers.
 * @returns {Amount} Satoshis.
 * @throws on parse error
 */

Amount.parseUnsafe = function parseUnsafe(value, dec, num) {
  if (typeof value === 'string') {
    assert(util.isFloat(value), 'Non-BTC value for conversion.');
    value = parseFloat(value, 10);
  } else {
    assert(util.isNumber(value), 'Non-BTC value for conversion.');
    assert(num, 'Cannot parse number.');
  }

  value *= pow10(dec);

  assert(value % 1 === 0, 'Too many decimal places.');

  return value;
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
    default:
      assert(false);
  }
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
    default:
      assert(false);
  }
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
    default:
      assert(false);
  }
}

/*
 * Expose
 */

module.exports = Amount;
