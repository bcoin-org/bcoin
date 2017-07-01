/*!
 * scriptnum.js - script number for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const ScriptError = require('./common').ScriptError;
const EMPTY_ARRAY = Buffer.alloc(0);

/**
 * ScriptNum
 * @alias module:script.ScriptNum
 * @constructor
 * @ignore
 * @param {Number} value
 */

function ScriptNum(value) {
  if (!(this instanceof ScriptNum))
    return new ScriptNum(value);

  assert(!value || value <= 0xffffffffffff, 'Number exceeds 2^48-1.');

  this.value = value || 0;
}

ScriptNum.prototype.clone = function clone() {
  return new ScriptNum(this.value);
};

ScriptNum.prototype.add = function add(num) {
  return this.clone().iadd(num);
};

ScriptNum.prototype.sub = function sub(num) {
  return this.clone().isub(num);
};

ScriptNum.prototype.mul = function mul(num) {
  return this.clone().imul(num);
};

ScriptNum.prototype.div = function div(num) {
  return this.clone().idiv(num);
};

ScriptNum.prototype.iadd = function iadd(num) {
  return this.iaddn(num.value);
};

ScriptNum.prototype.isub = function isub(num) {
  return this.isubn(num.value);
};

ScriptNum.prototype.imul = function imul(num) {
  return this.imuln(num.value);
};

ScriptNum.prototype.idiv = function idiv(num) {
  return this.idivn(num.value);
};

ScriptNum.prototype.addn = function addn(value) {
  return this.clone().iaddn(value);
};

ScriptNum.prototype.subn = function subn(value) {
  return this.clone().isubn(value);
};

ScriptNum.prototype.muln = function muln(value) {
  return this.clone().imuln(value);
};

ScriptNum.prototype.divn = function divn(value) {
  return this.clone().idivn(value);
};

ScriptNum.prototype.ushln = function ushln(value) {
  return this.clone().iushln(value);
};

ScriptNum.prototype.ushrn = function ushrn(value) {
  return this.clone().iushrn(value);
};

ScriptNum.prototype.iaddn = function addn(value) {
  this.value += value;
  return this;
};

ScriptNum.prototype.isubn = function subn(value) {
  this.value -= value;
  return this;
};

ScriptNum.prototype.imuln = function muln(value) {
  this.value *= value;
  return this;
};

ScriptNum.prototype.idivn = function divn(value) {
  this.value = Math.floor(this.value / value);
  return this;
};

ScriptNum.prototype.iushln = function iushln(value) {
  this.value *= Math.pow(2, value);
  return this;
};

ScriptNum.prototype.iushrn = function iushrn(value) {
  this.value = Math.floor(this.value / Math.pow(2, value));
  return this;
};

ScriptNum.prototype.cmp = function cmp(num) {
  return this.cmpn(num.value);
};

ScriptNum.prototype.cmpn = function cmpn(value) {
  if (this.value === value)
    return 0;
  return this.value < value ? -1 : 1;
};

ScriptNum.prototype.neg = function neg() {
  return this.clone().ineg();
};

ScriptNum.prototype.ineg = function ineg() {
  this.value = -this.value;
  return this;
};

ScriptNum.prototype.toNumber = function toNumber() {
  return this.value;
};

ScriptNum.prototype.toString = function toString(base) {
  if (!base)
    base = 10;

  if (base === 10 || base === 'dec')
    return this.value.toString(10);

  if (base === 16 || base === 'hex') {
    let str = this.value.toString(16);
    if (str.length % 2 !== 0)
      str = '0' + str;
    return str;
  }

  assert(false, `Base ${base} not supported.`);
};

ScriptNum.prototype.toJSON = function toJSON() {
  return this.toString(16);
};

ScriptNum.prototype.fromString = function fromString(str, base) {
  let nonzero = 0;
  let negative = false;

  if (!base)
    base = 10;

  if (str[0] === '-') {
    assert(str.length > 1, 'Non-numeric string passed.');
    str = str.substring(1);
    negative = true;
  } else {
    assert(str.length > 0, 'Non-numeric string passed.');
  }

  this.value = 0;

  if (base === 10 || base === 'dec') {
    for (let i = 0; i < str.length; i++) {
      let ch = str[i];

      if (nonzero === 0 && ch === '0')
        continue;

      if (!(ch >= '0' && ch <= '9'))
        throw new Error('Parse error.');

      ch = ch.charCodeAt(0) - 48;

      nonzero++;
      assert(nonzero <= 15, 'Number exceeds 2^48-1.');

      this.value *= 10;
      this.value += ch;
    }

    if (negative)
      this.value = -this.value;

    return this;
  }

  if (base === 16 || base === 'hex') {
    for (let i = 0; i < str.length; i++) {
      let ch = str[i];

      if (nonzero === 0 && ch === '0')
        continue;

      if (ch >= '0' && ch <= '9') {
        ch = ch.charCodeAt(0);
        ch -= 48;
      } else if (ch >= 'a' && ch <= 'f') {
        ch = ch.charCodeAt(0);
        ch -= 87;
      } else if (ch >= 'A' && ch <= 'F') {
        ch = ch.charCodeAt(0);
        ch -= 55;
      } else {
        throw new Error('Parse error.');
      }

      nonzero++;
      assert(nonzero <= 12, 'Number exceeds 2^48-1.');

      this.value *= 16;
      this.value += ch;
    }

    if (negative)
      this.value = -this.value;

    return this;
  }

  assert(false, `Base ${base} not supported.`);
};

ScriptNum.fromString = function fromString(str, base) {
  return new ScriptNum(0).fromString(str, base);
};

ScriptNum.prototype.fromRaw = function fromRaw(data, minimal, limit) {
  if (minimal == null)
    minimal = true;

  if (limit == null)
    limit = 4;

  // We can't handle more than 6 bytes.
  assert(limit <= 6, 'Number exceeds 48 bits.');

  // Max size is 4 bytes by default, 6 bytes max.
  if (data.length > limit)
    throw new ScriptError('UNKNOWN_ERROR', 'Script number overflow.');

  // Empty arrays are always zero.
  if (data.length === 0) {
    this.value = 0;
    return this;
  }

  // Ensure minimal serialization.
  if (minimal) {
    if ((data[data.length - 1] & 0x7f) === 0) {
      if (data.length === 1 || !(data[data.length - 2] & 0x80)) {
        throw new ScriptError(
          'UNKNOWN_ERROR',
          'Non-minimally encoded Script number.');
      }
    }
  }

  this.value = 0;

  // Read number (6 bytes max).
  switch (data.length) {
    case 6:
      this.value += data[5] * 0x10000000000;
    case 5:
      this.value += data[4] * 0x100000000;
    case 4:
      this.value += data[3] * 0x1000000;
    case 3:
      this.value += data[2] * 0x10000;
    case 2:
      this.value += data[1] * 0x100;
    case 1:
      this.value += data[0];
  }

  // Remove high bit and flip sign.
  if (data[data.length - 1] & 0x80) {
    switch (data.length) {
      case 1:
      case 2:
      case 3:
      case 4:
        this.value &= ~(0x80 << (8 * (data.length - 1)));
        break;
      case 5:
        this.value -= 0x8000000000;
        break;
      case 6:
        this.value -= 0x800000000000;
        break;
    }
    this.value = -this.value;
  }

  return this;
};

ScriptNum.fromRaw = function fromRaw(data, minimal, limit) {
  return new ScriptNum(0).fromRaw(data, minimal, limit);
};

ScriptNum.prototype.toRaw = function toRaw() {
  let value = this.value;
  let negative = false;
  let data, offset, size;

  // Zeroes are always empty arrays.
  if (value === 0)
    return EMPTY_ARRAY;

  // Need to append sign bit.
  if (value < 0) {
    negative = true;
    value = -value;
  }

  // Gauge buffer size.
  if (value <= 0xff) {
    offset = (value & 0x80) ? 1 : 0;
    size = 1;
  } else if (value <= 0xffff) {
    offset = (value & 0x8000) ? 1 : 0;
    size = 2;
  } else if (value <= 0xffffff) {
    offset = (value & 0x800000) ? 1 : 0;
    size = 3;
  } else if (value <= 0xffffffff) {
    offset = (value & 0x80000000) ? 1 : 0;
    size = 4;
  } else if (value <= 0xffffffffff) {
    offset = value >= 0x8000000000 ? 1 : 0;
    size = 5;
  } else if (value <= 0xffffffffffff) {
    offset = value >= 0x800000000000 ? 1 : 0;
    size = 6;
  } else {
    throw new ScriptError('UNKNOWN_ERROR', 'Script number overflow.');
  }

  // Write number.
  data = Buffer.allocUnsafe(size + offset);

  switch (size) {
    case 6:
      data[5] = (value / 0x10000000000 | 0) & 0xff;
    case 5:
      data[4] = (value / 0x100000000 | 0) & 0xff;
    case 4:
      data[3] = (value >>> 24) & 0xff;
    case 3:
      data[2] = (value >> 16) & 0xff;
    case 2:
      data[1] = (value >> 8) & 0xff;
    case 1:
      data[0] = value & 0xff;
  }

  // Append sign bit.
  if (data[size - 1] & 0x80)
    data[size] = negative ? 0x80 : 0;
  else if (negative)
    data[size - 1] |= 0x80;

  return data;
};

/*
 * Expose
 */

module.exports = ScriptNum;
