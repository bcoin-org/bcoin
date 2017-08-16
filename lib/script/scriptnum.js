/*!
 * scriptnum.js - script number for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const {I64} = require('../utils/int64');
const {ScriptError} = require('./common');
const EMPTY_ARRAY = Buffer.alloc(0);

function ScriptNum(num, base, limit) {
  if (!(this instanceof ScriptNum))
    return new ScriptNum(num, base, limit);

  I64.call(this, num, base, limit);
}

Object.setPrototypeOf(ScriptNum, I64);
Object.setPrototypeOf(ScriptNum.prototype, I64.prototype);

ScriptNum.prototype.toInt = function toInt() {
  if (this.lt(I64.UINT32_MIN))
    return I64.LONG_MIN;

  if (this.gt(I64.UINT32_MAX))
    return I64.LONG_MAX;

  return this.lo;
};

ScriptNum.prototype.toRaw = function toRaw() {
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
};

ScriptNum.prototype.fromRaw = function fromRaw(data) {
  assert(Buffer.isBuffer(data));

  // Empty arrays are always zero.
  if (data.length === 0)
    return this;

  // Read number (9 bytes max).
  switch (data.length) {
    case 9:
      // Note: this shift overflows to
      // zero in modern bitcoin core.
      this.lo |= data[8];
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
  }

  // Remove high bit and flip sign.
  if (data[data.length - 1] & 0x80) {
    this.setn((data.length * 8) - 1, 0);
    this.ineg();
  }

  return this;
};

ScriptNum.prototype.decode = function decode(data, minimal, limit) {
  assert(Buffer.isBuffer(data));

  if (minimal == null)
    minimal = true;

  if (limit == null)
    limit = 4;

  // We can't handle more than 9 bytes.
  assert(limit >= 4 && limit <= 9, 'Bad script number size limit.');

  // Max size is 4 bytes by default, 9 bytes max.
  if (data.length > limit)
    throw new ScriptError('UNKNOWN_ERROR', 'Script number overflow.');

  // Ensure minimal serialization.
  if (minimal && !ScriptNum.isMinimal(data))
    throw new ScriptError('UNKNOWN_ERROR', 'Non-minimal script number.');

  return this.fromRaw(data);
};

ScriptNum.prototype.inspect = function inspect() {
  return `<ScriptNum: ${this.toString(10)}>`;
};

ScriptNum.isMinimal = function isMinimal(data) {
  assert(Buffer.isBuffer(data));

  if (data.length === 0)
    return true;

  if ((data[data.length - 1] & 0x7f) === 0) {
    if (data.length === 1)
      return false;

    if (!(data[data.length - 2] & 0x80))
      return false;
  }

  return true;
};

ScriptNum.decode = function decode(data, minimal, limit) {
  return new ScriptNum().decode(data, minimal, limit);
};

ScriptNum.isScriptNum = function isScriptNum(obj) {
  return obj instanceof ScriptNum;
};
