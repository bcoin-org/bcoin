/*!
 * scriptnum.js - script number object for bcoin.
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const {I64} = require('n64');
const ScriptError = require('./scripterror');

/*
 * Constants
 */

const EMPTY_ARRAY = Buffer.alloc(0);

/**
 * Script Number
 * @see https://github.com/chjj/n64
 * @alias module:script.ScriptNum
 * @property {Number} hi
 * @property {Number} lo
 * @property {Number} sign
 */

class ScriptNum extends I64 {
  /**
   * Create a script number.
   * @constructor
   * @param {(Number|String|Buffer|Object)?} num
   * @param {(String|Number)?} base
   */

  constructor(num, base) {
    super(num, base);
  }

  /**
   * Cast to int32.
   * @returns {Number}
   */

  getInt() {
    if (this.lt(I64.INT32_MIN))
      return I64.LONG_MIN;

    if (this.gt(I64.INT32_MAX))
      return I64.LONG_MAX;

    return this.toInt();
  }

  /**
   * Serialize script number.
   * @returns {Buffer}
   */

  toRaw() {
    let num = this;

    // Zeroes are always empty arrays.
    if (num.isZero())
      return EMPTY_ARRAY;

    // Need to append sign bit.
    let neg = false;
    if (num.isNeg()) {
      num = num.neg();
      neg = true;
    }

    // Calculate size.
    const size = num.byteLength();

    let offset = 0;

    if (num.testn((size * 8) - 1))
      offset = 1;

    // Write number.
    const data = Buffer.allocUnsafe(size + offset);

    switch (size) {
      case 8:
        data[7] = (num.hi >>> 24) & 0xff;
      case 7:
        data[6] = (num.hi >> 16) & 0xff;
      case 6:
        data[5] = (num.hi >> 8) & 0xff;
      case 5:
        data[4] = num.hi & 0xff;
      case 4:
        data[3] = (num.lo >>> 24) & 0xff;
      case 3:
        data[2] = (num.lo >> 16) & 0xff;
      case 2:
        data[1] = (num.lo >> 8) & 0xff;
      case 1:
        data[0] = num.lo & 0xff;
    }

    // Append sign bit.
    if (data[size - 1] & 0x80) {
      assert(offset === 1);
      assert(data.length === size + offset);
      data[size] = neg ? 0x80 : 0;
    } else if (neg) {
      assert(offset === 0);
      assert(data.length === size);
      data[size - 1] |= 0x80;
    } else {
      assert(offset === 0);
      assert(data.length === size);
    }

    return data;
  }

  /**
   * Instantiate script number from serialized data.
   * @private
   * @param {Buffer} data
   * @returns {ScriptNum}
   */

  fromRaw(data) {
    assert(Buffer.isBuffer(data));

    // Empty arrays are always zero.
    if (data.length === 0)
      return this;

    // Read number (9 bytes max).
    switch (data.length) {
      case 8:
        this.hi |= data[7] << 24;
      case 7:
        this.hi |= data[6] << 16;
      case 6:
        this.hi |= data[5] << 8;
      case 5:
        this.hi |= data[4];
      case 4:
        this.lo |= data[3] << 24;
      case 3:
        this.lo |= data[2] << 16;
      case 2:
        this.lo |= data[1] << 8;
      case 1:
        this.lo |= data[0];
        break;
      default:
        for (let i = 0; i < data.length; i++)
          this.orb(i, data[i]);
        break;
    }

    // Remove high bit and flip sign.
    if (data[data.length - 1] & 0x80) {
      this.setn((data.length * 8) - 1, 0);
      this.ineg();
    }

    return this;
  }

  /**
   * Serialize script number.
   * @returns {Buffer}
   */

  encode() {
    return this.toRaw();
  }

  /**
   * Decode and verify script number.
   * @private
   * @param {Buffer} data
   * @param {Boolean?} minimal - Require minimal encoding.
   * @param {Number?} limit - Size limit.
   * @returns {ScriptNum}
   */

  decode(data, minimal, limit) {
    assert(Buffer.isBuffer(data));

    if (limit != null && data.length > limit)
      throw new ScriptError('UNKNOWN_ERROR', 'Script number overflow.');

    if (minimal && !ScriptNum.isMinimal(data))
      throw new ScriptError('UNKNOWN_ERROR', 'Non-minimal script number.');

    return this.fromRaw(data);
  }

  /**
   * Inspect script number.
   * @returns {String}
   */

  inspect() {
    return `<ScriptNum: ${this.toString(10)}>`;
  }

  /**
   * Test wether a serialized script
   * number is in its most minimal form.
   * @param {Buffer} data
   * @returns {Boolean}
   */

  static isMinimal(data) {
    assert(Buffer.isBuffer(data));

    if (data.length === 0)
      return true;

    if ((data[data.length - 1] & 0x7f) === 0) {
      if (data.length === 1)
        return false;

      if ((data[data.length - 2] & 0x80) === 0)
        return false;
    }

    return true;
  }

  /**
   * Decode and verify script number.
   * @param {Buffer} data
   * @param {Boolean?} minimal - Require minimal encoding.
   * @param {Number?} limit - Size limit.
   * @returns {ScriptNum}
   */

  static decode(data, minimal, limit) {
    return new this().decode(data, minimal, limit);
  }

  /**
   * Test whether object is a script number.
   * @param {Object} obj
   * @returns {Boolean}
   */

  static isScriptNum(obj) {
    return obj instanceof ScriptNum;
  }
}

/*
 * Expose
 */

module.exports = ScriptNum;
