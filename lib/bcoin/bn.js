/**
 * bn.js - signed big numbers for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bn = require('bn.js');

/**
 * Signed Big Numbers
 */

function bn2(number, signed, base, endian) {
  if (!(this instanceof bn2))
    return new bn2(number, signed, base, endian);

  if (typeof signed !== 'boolean') {
    endian = base;
    base = signed;
    signed = null;
  }

  this.__signed = !!signed;

  return bn.call(this, number, base, endian);
}

bn2.prototype.__proto__ = bn.prototype;

bn2.prototype._initArray = function _initArray(number, base, endian) {
  var i = 0;
  var ret;

  if (!this.__signed)
    return bn.prototype._initArray.apply(this, arguments);

  if (endian === 'le')
    i = number.length - 1;

  // If we are signed, do (~num + 1) to get
  // the positive counterpart and set bn's
  // negative flag.
  if (number[i] & 0x80) {
    if (isNegZero(number, endian)) {
      ret = this._initNumber(0, 10, endian);
    } else {
      ret = bn.prototype._initArray.apply(this, arguments);
      this.inotn(64).iaddn(1).ineg();
    }
  } else {
    ret = bn.prototype._initArray.apply(this, arguments);
  }

  return ret;
};

bn2.prototype.toArray = function toArray(endian, length) {
  var self = this;

  if (!this.__signed)
    return bn.prototype.toArray.apply(self, arguments);

  // Convert the number to the
  // negative byte representation.
  if (self.isNeg()) {
    if (self.cmpn(0) === 0)
      self = new bn(0);
    else
      self = self.neg().notn(64).addn(1);
  }

  return bn.prototype.toArray.apply(self, arguments);
};

bn2.signed = function signed(number, base, endian) {
  return new bn2(number, true, base, endian);
};

function isNegZero(number, endian) {
  var i = 0;

  if (endian === 'le')
    i = number.length - 1;

  if (number[i] & 0x80) {
    number = number.slice();
    number[i] &= ~0x80;
    return new bn(number, endian).cmpn(0) === 0;
  }

  return false;
}

/**
 * Expose
 */

module.exports = bn2;
