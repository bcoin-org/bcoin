/*!
 * amount.js - amount object for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const util = require('../utils/util');

/**
 * Represents a bitcoin amount (satoshis internally).
 * @alias module:btc.Amount
 * @constructor
 * @param {(String|Number)?} value
 * @param {String?} unit
 * @param {Boolean?} num
 * @property {Amount} value
 */

function Amount(value, unit, num) {
  if (!(this instanceof Amount))
    return new Amount(value, unit, num);

  this.value = 0;

  if (value != null)
    this.fromOptions(value, unit, num);
}

/**
 * Inject properties from options.
 * @private
 * @param {(String|Number)?} value
 * @param {String?} unit
 * @param {Boolean?} num
 * @returns {Amount}
 */

Amount.prototype.fromOptions = function fromOptions(value, unit, num) {
  if (typeof unit === 'string')
    return this.from(unit, value, num);

  if (typeof value === 'number')
    return this.fromValue(value);

  return this.fromBTC(value);
};

/**
 * Get satoshi value.
 * @returns {Amount}
 */

Amount.prototype.toValue = function toValue() {
  return this.value;
};

/**
 * Get satoshi string or value.
 * @param {Boolean?} num
 * @returns {String|Amount}
 */

Amount.prototype.toSatoshis = function toSatoshis(num) {
  if (num)
    return this.value;

  return this.value.toString(10);
};

/**
 * Get bits string or value.
 * @param {Boolean?} num
 * @returns {String|Amount}
 */

Amount.prototype.toBits = function toBits(num) {
  return Amount.serialize(this.value, 2, num);
};

/**
 * Get mbtc string or value.
 * @param {Boolean?} num
 * @returns {String|Amount}
 */

Amount.prototype.toMBTC = function toMBTC(num) {
  return Amount.serialize(this.value, 5, num);
};

/**
 * Get btc string or value.
 * @param {Boolean?} num
 * @returns {String|Amount}
 */

Amount.prototype.toBTC = function toBTC(num) {
  return Amount.serialize(this.value, 8, num);
};

/**
 * Get unit string or value.
 * @param {String} unit - Can be `sat`,
 * `ubtc`, `bits`, `mbtc`, or `btc`.
 * @param {Boolean?} num
 * @returns {String|Amount}
 */

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
  throw new Error(`Unknown unit "${unit}".`);
};

/**
 * Convert amount to bitcoin string.
 * @returns {String}
 */

Amount.prototype.toString = function toString() {
  return this.toBTC();
};

/**
 * Inject properties from value.
 * @private
 * @param {Amount} value
 * @returns {Amount}
 */

Amount.prototype.fromValue = function fromValue(value) {
  assert(util.isInt53(value), 'Value must be an int64.');
  this.value = value;
  return this;
};

/**
 * Inject properties from satoshis.
 * @private
 * @param {Number|String} value
 * @param {Bolean?} num
 * @returns {Amount}
 */

Amount.prototype.fromSatoshis = function fromSatoshis(value, num) {
  this.value = Amount.parse(value, 0, num);
  return this;
};

/**
 * Inject properties from bits.
 * @private
 * @param {Number|String} value
 * @param {Bolean?} num
 * @returns {Amount}
 */

Amount.prototype.fromBits = function fromBits(value, num) {
  this.value = Amount.parse(value, 2, num);
  return this;
};

/**
 * Inject properties from mbtc.
 * @private
 * @param {Number|String} value
 * @param {Bolean?} num
 * @returns {Amount}
 */

Amount.prototype.fromMBTC = function fromMBTC(value, num) {
  this.value = Amount.parse(value, 5, num);
  return this;
};

/**
 * Inject properties from btc.
 * @private
 * @param {Number|String} value
 * @param {Bolean?} num
 * @returns {Amount}
 */

Amount.prototype.fromBTC = function fromBTC(value, num) {
  this.value = Amount.parse(value, 8, num);
  return this;
};

/**
 * Inject properties from unit.
 * @private
 * @param {String} unit
 * @param {Number|String} value
 * @param {Bolean?} num
 * @returns {Amount}
 */

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
  throw new Error(`Unknown unit "${unit}".`);
};

/**
 * Instantiate amount from options.
 * @param {(String|Number)?} value
 * @param {String?} unit
 * @param {Boolean?} num
 * @returns {Amount}
 */

Amount.fromOptions = function fromOptions(value, unit, num) {
  return new Amount().fromOptions(value);
};

/**
 * Instantiate amount from value.
 * @private
 * @param {Amount} value
 * @returns {Amount}
 */

Amount.fromValue = function fromValue(value) {
  return new Amount().fromValue(value);
};

/**
 * Instantiate amount from satoshis.
 * @param {Number|String} value
 * @param {Bolean?} num
 * @returns {Amount}
 */

Amount.fromSatoshis = function fromSatoshis(value, num) {
  return new Amount().fromSatoshis(value, num);
};

/**
 * Instantiate amount from bits.
 * @param {Number|String} value
 * @param {Bolean?} num
 * @returns {Amount}
 */

Amount.fromBits = function fromBits(value, num) {
  return new Amount().fromBits(value, num);
};

/**
 * Instantiate amount from mbtc.
 * @param {Number|String} value
 * @param {Bolean?} num
 * @returns {Amount}
 */

Amount.fromMBTC = function fromMBTC(value, num) {
  return new Amount().fromMBTC(value, num);
};

/**
 * Instantiate amount from btc.
 * @param {Number|String} value
 * @param {Bolean?} num
 * @returns {Amount}
 */

Amount.fromBTC = function fromBTC(value, num) {
  return new Amount().fromBTC(value, num);
};

/**
 * Instantiate amount from unit.
 * @param {String} unit
 * @param {Number|String} value
 * @param {Bolean?} num
 * @returns {Amount}
 */

Amount.from = function from(unit, value, num) {
  return new Amount().from(unit, value, num);
};

/**
 * Inspect amount.
 * @returns {String}
 */

Amount.prototype.inspect = function inspect() {
  return `<Amount: ${this.toString()}>`;
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
 * @param {Number} exp - Exponent.
 * @param {Boolean} num - Return a number.
 * @returns {String}
 */

Amount.serialize = function serialize(value, exp, num) {
  let negative = false;
  let hi, lo, result;

  assert(util.isInt(value), 'Non-satoshi value for conversion.');

  if (value < 0) {
    value = -value;
    negative = true;
  }

  value = value.toString(10);

  assert(value.length <= 16, 'Number exceeds 2^53-1.');

  while (value.length < exp + 1)
    value = '0' + value;

  hi = value.slice(0, -exp);
  lo = value.slice(-exp);

  lo = lo.replace(/0+$/, '');

  if (lo.length === 0)
    lo += '0';

  result = `${hi}.${lo}`;

  if (negative)
    result = '-' + result;

  if (num)
    return +result;

  return result;
};

/**
 * Unsafely convert satoshis to a BTC string.
 * @param {Amount} value
 * @param {Number} exp - Exponent.
 * @param {Boolean} num - Return a number.
 * @returns {String}
 */

Amount.serializeUnsafe = function serializeUnsafe(value, exp, num) {
  assert(util.isInt(value), 'Non-satoshi value for conversion.');

  value /= pow10(exp);
  value = value.toFixed(exp);

  if (num)
    return +value;

  if (exp !== 0) {
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

Amount.value = function _value(value, num) {
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
 * @param {Number} exp - Exponent.
 * @param {Boolean} num - Allow numbers.
 * @returns {Amount} Satoshis.
 * @throws on parse error
 */

Amount.parse = function parse(value, exp, num) {
  let negative = false;
  let mult = pow10(exp);
  let maxLo = modSafe(mult);
  let maxHi = divSafe(mult);
  let parts, hi, lo, result;

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

  assert(hi.length <= 16 - exp, 'Number exceeds 2^53-1.');
  assert(lo.length <= exp, 'Too many decimal places.');

  if (hi.length === 0)
    hi = '0';

  while (lo.length < exp)
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
 * @param {Number} exp - Exponent.
 * @param {Boolean} num - Allow numbers.
 * @returns {Amount} Satoshis.
 * @throws on parse error
 */

Amount.parseUnsafe = function parseUnsafe(value, exp, num) {
  if (typeof value === 'string') {
    assert(util.isFloat(value), 'Non-BTC value for conversion.');
    value = parseFloat(value);
  } else {
    assert(util.isNumber(value), 'Non-BTC value for conversion.');
    assert(num, 'Cannot parse number.');
  }

  value *= pow10(exp);

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
      assert(false, 'Exponent is too large.');
      break;
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
      assert(false, 'Exponent is too large.');
      break;
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
      assert(false, 'Exponent is too large.');
      break;
  }
}

/*
 * Expose
 */

module.exports = Amount;
