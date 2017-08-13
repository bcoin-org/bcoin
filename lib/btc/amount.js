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
 * @property {Amount} value
 */

function Amount(value, unit) {
  if (!(this instanceof Amount))
    return new Amount(value, unit);

  this.value = 0;

  if (value != null)
    this.fromOptions(value, unit);
}

/**
 * Inject properties from options.
 * @private
 * @param {(String|Number)?} value
 * @param {String?} unit
 * @returns {Amount}
 */

Amount.prototype.fromOptions = function fromOptions(value, unit) {
  if (typeof unit === 'string')
    return this.from(unit, value);

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
  return Amount.encode(this.value, 2, num);
};

/**
 * Get mbtc string or value.
 * @param {Boolean?} num
 * @returns {String|Amount}
 */

Amount.prototype.toMBTC = function toMBTC(num) {
  return Amount.encode(this.value, 5, num);
};

/**
 * Get btc string or value.
 * @param {Boolean?} num
 * @returns {String|Amount}
 */

Amount.prototype.toBTC = function toBTC(num) {
  return Amount.encode(this.value, 8, num);
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
  assert(util.isI64(value), 'Value must be an int64.');
  this.value = value;
  return this;
};

/**
 * Inject properties from satoshis.
 * @private
 * @param {Number|String} value
 * @returns {Amount}
 */

Amount.prototype.fromSatoshis = function fromSatoshis(value) {
  this.value = Amount.decode(value, 0);
  return this;
};

/**
 * Inject properties from bits.
 * @private
 * @param {Number|String} value
 * @returns {Amount}
 */

Amount.prototype.fromBits = function fromBits(value) {
  this.value = Amount.decode(value, 2);
  return this;
};

/**
 * Inject properties from mbtc.
 * @private
 * @param {Number|String} value
 * @returns {Amount}
 */

Amount.prototype.fromMBTC = function fromMBTC(value) {
  this.value = Amount.decode(value, 5);
  return this;
};

/**
 * Inject properties from btc.
 * @private
 * @param {Number|String} value
 * @returns {Amount}
 */

Amount.prototype.fromBTC = function fromBTC(value) {
  this.value = Amount.decode(value, 8);
  return this;
};

/**
 * Inject properties from unit.
 * @private
 * @param {String} unit
 * @param {Number|String} value
 * @returns {Amount}
 */

Amount.prototype.from = function from(unit, value) {
  switch (unit) {
    case 'sat':
      return this.fromSatoshis(value);
    case 'ubtc':
    case 'bits':
      return this.fromBits(value);
    case 'mbtc':
      return this.fromMBTC(value);
    case 'btc':
      return this.fromBTC(value);
  }
  throw new Error(`Unknown unit "${unit}".`);
};

/**
 * Instantiate amount from options.
 * @param {(String|Number)?} value
 * @param {String?} unit
 * @returns {Amount}
 */

Amount.fromOptions = function fromOptions(value, unit) {
  return new Amount().fromOptions(value, unit);
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
 * @returns {Amount}
 */

Amount.fromSatoshis = function fromSatoshis(value) {
  return new Amount().fromSatoshis(value);
};

/**
 * Instantiate amount from bits.
 * @param {Number|String} value
 * @returns {Amount}
 */

Amount.fromBits = function fromBits(value) {
  return new Amount().fromBits(value);
};

/**
 * Instantiate amount from mbtc.
 * @param {Number|String} value
 * @returns {Amount}
 */

Amount.fromMBTC = function fromMBTC(value) {
  return new Amount().fromMBTC(value);
};

/**
 * Instantiate amount from btc.
 * @param {Number|String} value
 * @returns {Amount}
 */

Amount.fromBTC = function fromBTC(value) {
  return new Amount().fromBTC(value);
};

/**
 * Instantiate amount from unit.
 * @param {String} unit
 * @param {Number|String} value
 * @returns {Amount}
 */

Amount.from = function from(unit, value) {
  return new Amount().from(unit, value);
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
  if (typeof value === 'string')
    return value;

  return Amount.encode(value, 8, num);
};

/**
 * Safely convert a BTC string to satoshis.
 * @param {String} str - BTC
 * @returns {Amount} Satoshis.
 * @throws on parse error
 */

Amount.value = function value(str) {
  if (typeof str === 'number')
    return str;

  return Amount.decode(str, 8);
};

/**
 * Safely convert satoshis to a BTC string.
 * @param {Amount} value
 * @param {Number} exp - Exponent.
 * @param {Boolean} num - Return a number.
 * @returns {String|Number}
 */

Amount.encode = function encode(value, exp, num) {
  if (num)
    return util.toFloat(value, exp);
  return util.toFixed(value, exp);
};

/**
 * Safely convert a BTC string to satoshis.
 * @param {String|Number} value - BTC
 * @param {Number} exp - Exponent.
 * @returns {Amount} Satoshis.
 * @throws on parse error
 */

Amount.decode = function decode(value, exp) {
  if (typeof value === 'number')
    return util.fromFloat(value, exp);
  return util.fromFixed(value, exp);
};

/*
 * Expose
 */

module.exports = Amount;
