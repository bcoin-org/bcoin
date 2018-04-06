/*!
 * amount.js - amount object for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const fixed = require('../utils/fixed');

/**
 * Amount
 * Represents a bitcoin amount (satoshis internally).
 * @alias module:btc.Amount
 * @property {Amount} value
 */

class Amount {
  /**
   * Create an amount.
   * @constructor
   * @param {(String|Number)?} value
   * @param {String?} unit
   */

  constructor(value, unit) {
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

  fromOptions(value, unit) {
    if (typeof unit === 'string')
      return this.from(unit, value);

    if (typeof value === 'number')
      return this.fromValue(value);

    return this.fromBTC(value);
  }

  /**
   * Get satoshi value.
   * @returns {Amount}
   */

  toValue() {
    return this.value;
  }

  /**
   * Get satoshi string or value.
   * @param {Boolean?} num
   * @returns {String|Amount}
   */

  toSatoshis(num) {
    if (num)
      return this.value;

    return this.value.toString(10);
  }

  /**
   * Get bits string or value.
   * @param {Boolean?} num
   * @returns {String|Amount}
   */

  toBits(num) {
    return Amount.encode(this.value, 2, num);
  }

  /**
   * Get mbtc string or value.
   * @param {Boolean?} num
   * @returns {String|Amount}
   */

  toMBTC(num) {
    return Amount.encode(this.value, 5, num);
  }

  /**
   * Get btc string or value.
   * @param {Boolean?} num
   * @returns {String|Amount}
   */

  toBTC(num) {
    return Amount.encode(this.value, 8, num);
  }

  /**
   * Get unit string or value.
   * @param {String} unit - Can be `sat`,
   * `ubtc`, `bits`, `mbtc`, or `btc`.
   * @param {Boolean?} num
   * @returns {String|Amount}
   */

  to(unit, num) {
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
  }

  /**
   * Convert amount to bitcoin string.
   * @returns {String}
   */

  toString() {
    return this.toBTC();
  }

  /**
   * Inject properties from value.
   * @private
   * @param {Amount} value
   * @returns {Amount}
   */

  fromValue(value) {
    assert(Number.isSafeInteger(value) && value >= 0,
      'Value must be an int64.');
    this.value = value;
    return this;
  }

  /**
   * Inject properties from satoshis.
   * @private
   * @param {Number|String} value
   * @returns {Amount}
   */

  fromSatoshis(value) {
    this.value = Amount.decode(value, 0);
    return this;
  }

  /**
   * Inject properties from bits.
   * @private
   * @param {Number|String} value
   * @returns {Amount}
   */

  fromBits(value) {
    this.value = Amount.decode(value, 2);
    return this;
  }

  /**
   * Inject properties from mbtc.
   * @private
   * @param {Number|String} value
   * @returns {Amount}
   */

  fromMBTC(value) {
    this.value = Amount.decode(value, 5);
    return this;
  }

  /**
   * Inject properties from btc.
   * @private
   * @param {Number|String} value
   * @returns {Amount}
   */

  fromBTC(value) {
    this.value = Amount.decode(value, 8);
    return this;
  }

  /**
   * Inject properties from unit.
   * @private
   * @param {String} unit
   * @param {Number|String} value
   * @returns {Amount}
   */

  from(unit, value) {
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
  }

  /**
   * Instantiate amount from options.
   * @param {(String|Number)?} value
   * @param {String?} unit
   * @returns {Amount}
   */

  static fromOptions(value, unit) {
    return new this().fromOptions(value, unit);
  }

  /**
   * Instantiate amount from value.
   * @private
   * @param {Amount} value
   * @returns {Amount}
   */

  static fromValue(value) {
    return new this().fromValue(value);
  }

  /**
   * Instantiate amount from satoshis.
   * @param {Number|String} value
   * @returns {Amount}
   */

  static fromSatoshis(value) {
    return new this().fromSatoshis(value);
  }

  /**
   * Instantiate amount from bits.
   * @param {Number|String} value
   * @returns {Amount}
   */

  static fromBits(value) {
    return new this().fromBits(value);
  }

  /**
   * Instantiate amount from mbtc.
   * @param {Number|String} value
   * @returns {Amount}
   */

  static fromMBTC(value) {
    return new this().fromMBTC(value);
  }

  /**
   * Instantiate amount from btc.
   * @param {Number|String} value
   * @returns {Amount}
   */

  static fromBTC(value) {
    return new this().fromBTC(value);
  }

  /**
   * Instantiate amount from unit.
   * @param {String} unit
   * @param {Number|String} value
   * @returns {Amount}
   */

  static from(unit, value) {
    return new this().from(unit, value);
  }

  /**
   * Inspect amount.
   * @returns {String}
   */

  inspect() {
    return `<Amount: ${this.toString()}>`;
  }

  /**
   * Safely convert satoshis to a BTC string.
   * This function explicitly avoids any
   * floating point arithmetic.
   * @param {Amount} value - Satoshis.
   * @returns {String} BTC string.
   */

  static btc(value, num) {
    if (typeof value === 'string')
      return value;

    return Amount.encode(value, 8, num);
  }

  /**
   * Safely convert a BTC string to satoshis.
   * @param {String} str - BTC
   * @returns {Amount} Satoshis.
   * @throws on parse error
   */

  static value(str) {
    if (typeof str === 'number')
      return str;

    return Amount.decode(str, 8);
  }

  /**
   * Safely convert satoshis to a BTC string.
   * @param {Amount} value
   * @param {Number} exp - Exponent.
   * @param {Boolean} num - Return a number.
   * @returns {String|Number}
   */

  static encode(value, exp, num) {
    if (num)
      return fixed.toFloat(value, exp);
    return fixed.encode(value, exp);
  }

  /**
   * Safely convert a BTC string to satoshis.
   * @param {String|Number} value - BTC
   * @param {Number} exp - Exponent.
   * @returns {Amount} Satoshis.
   * @throws on parse error
   */

  static decode(value, exp) {
    if (typeof value === 'number')
      return fixed.fromFloat(value, exp);
    return fixed.decode(value, exp);
  }
}

/*
 * Expose
 */

module.exports = Amount;
