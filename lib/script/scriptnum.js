/*!
 * scriptnum.js - script number for bcoin
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var util = require('../utils/util');
var ScriptError = require('../btc/errors').ScriptError;
var constants = require('../protocol/constants');
var STACK_FALSE = new Buffer(0);

/**
 * ScriptNum
 * @constructor
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
  assert(false);
  this.value *= value;
  return this;
};

ScriptNum.prototype.idivn = function divn(value) {
  this.value = Math.floor(this.value / value);
  return this;
};

ScriptNum.prototype.iushln = function iushln(value) {
  assert(value === 1);
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

ScriptNum.prototype.fromString = function fromString(str, base) {
  var nonzero = 0;
  var neg = false;
  var i, ch;

  if (str[0] === '-') {
    assert(str.length > 1, 'Non-numeric string passed.');
    str = str.substring(1);
    neg = true;
  } else {
    assert(str.length > 0, 'Non-numeric string passed.');
  }

  this.value = 0;

  if (base === 10 || base === 'dec') {
    for (i = 0; i < str.length; i++) {
      ch = str[i];

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

    if (neg)
      this.value = -this.value;

    return this;
  }

  if (base === 16 || base === 'hex') {
    for (i = 0; i < str.length; i++) {
      ch = str[i];

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

    if (neg)
      this.value = -this.value;

    return this;
  }

  assert(false, 'Base ' + base + ' not supported.');
};

ScriptNum.fromString = function fromString(str, base) {
  return new ScriptNum(0).fromString(str, base);
};

ScriptNum.prototype.fromRaw = function fromRaw(value, flags, size) {
  var sign;

  assert(Buffer.isBuffer(value));

  if (flags == null)
    flags = constants.flags.STANDARD_VERIFY_FLAGS;

  if (size == null)
    size = 4;

  assert(size <= 6, 'Number exceeds 48 bits.');

  if (value.length === 0) {
    this.value = 0;
    return this;
  }

  if (value.length > size)
    throw new ScriptError('UNKNOWN_ERROR', 'Script number overflow.');

  if (flags & constants.flags.VERIFY_MINIMALDATA) {
    // If the low bits on the last byte are unset,
    // fail if the value's second to last byte does
    // not have the high bit set. A number can't
    // justify having the last byte's low bits unset
    // unless they ran out of space for the sign bit
    // in the second to last bit. We also fail on [0]
    // to avoid negative zero (also avoids positive
    // zero).
    if ((value[value.length - 1] & 0x7f) === 0) {
      if (value.length === 1 || !(value[value.length - 2] & 0x80)) {
        throw new ScriptError(
          'UNKNOWN_ERROR',
          'Non-minimally encoded Script number.');
      }
    }
  }

  this.value = 0;

  switch (value.length) {
    case 6:
      this.value += value[5] * 0x10000000000;
    case 5:
      this.value += value[4] * 0x100000000;
    case 4:
      this.value += value[3] * 0x1000000;
    case 3:
      this.value += value[2] * 0x10000;
    case 2:
      this.value += value[1] * 0x100;
    case 1:
      this.value += value[0];
      break;
    default:
      assert(false);
      break;
  }

  // If the input vector's most significant byte is
  // 0x80, remove it from the result's msb and return
  // a negative.
  // Equivalent to:
  // -(result & ~(0x80 << (8 * (value.length - 1))))
  if (value[value.length - 1] & 0x80) {
    switch (value.length) {
      case 1:
      case 2:
      case 3:
      case 4:
        sign = 0x80 << (8 * (value.length - 1));
        this.value &= ~sign;
        this.value = -this.value;
        break;
      case 5:
      case 6:
        sign = 0x80 * Math.pow(2, 8 * (value.length - 1));
        if (this.value >= sign)
          this.value -= sign;
        this.value = -this.value;
        break;
      default:
        assert(false);
        break;
    }
  }

  return this;
};

ScriptNum.fromRaw = function fromRaw(value, flags, size) {
  return new ScriptNum(0).fromRaw(value, flags, size);
};

ScriptNum.prototype.toRaw = function toRaw() {
  var value = this.value;
  var neg = false;
  var result, offset, size;

  if (value === 0)
    return STACK_FALSE;

  // If the most significant byte is >= 0x80
  // and the value is positive, push a new
  // zero-byte to make the significant
  // byte < 0x80 again.

  // If the most significant byte is >= 0x80
  // and the value is negative, push a new
  // 0x80 byte that will be popped off when
  // converting to an integral.

  // If the most significant byte is < 0x80
  // and the value is negative, add 0x80 to
  // it, since it will be subtracted and
  // interpreted as a negative when
  // converting to an integral.

  if (value < 0) {
    neg = true;
    value = -value;
  }

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

  result = new Buffer(size + offset);

  switch (size) {
    case 6:
      result[5] = (value / 0x10000000000 | 0) & 0xff;
    case 5:
      result[4] = (value / 0x100000000 | 0) & 0xff;
    case 4:
      result[3] = (value >>> 24) & 0xff;
    case 3:
      result[2] = (value >> 16) & 0xff;
    case 2:
      result[1] = (value >> 8) & 0xff;
    case 1:
      result[0] = value & 0xff;
      break;
    default:
      assert(false);
      break;
  }

  if (result[size - 1] & 0x80)
    result[result.length - 1] = neg ? 0x80 : 0;
  else if (neg)
    result[size - 1] |= 0x80;

  return result;
};

/*
 * Helpers
 */

function isDecimal(obj) {
  return typeof obj === 'string'
    && obj.length > 0
    && /^\-?[0-9]+$/i.test(obj);
}

function isHex(obj) {
  return typeof obj === 'string'
    && obj.length > 0
    && /^\-?[0-9a-f]+$/i.test(obj);
}

/*
 * Expose
 */

module.exports = ScriptNum;
