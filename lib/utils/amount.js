var utils = require('./utils');

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
  assert(utils.isInt53(value), 'Value must be an int64.');
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
    case 'bits':
      return this.fromBits(value, num);
    case 'mbtc':
      return this.fromMBTC(value, num);
    case 'btc':
      return this.fromBTC(value, num);
  }
  throw new Error('Unknown unit "' + unit + '".');
};

Amount.fromOptions = function fromOptions(value) {
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

Amount.btc = function btc(value) {
  if (utils.isFloat(value))
    return value;

  return Amount.serialize(value, 8, false);
};

/**
 * Safely convert satoshis to a BTC string.
 * This function explicitly avoids any
 * floating point arithmetic.
 * @param {Amount} value - Satoshis.
 * @returns {String} BTC string.
 */

Amount.serialize = function serialize(value, dec, num) {
  var negative = false;
  var hi, lo, result;

  assert(utils.isInt(value), 'Non-satoshi value for conversion.');

  if (value < 0) {
    value = -value;
    negative = true;
  }

  assert(value <= utils.MAX_SAFE_INTEGER, 'Number exceeds 2^53-1.');

  value = value.toString(10);

  assert(value.length <= 8 + dec, 'Number exceeds 2^53-1.');

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
 * Safely convert a BTC string to satoshis.
 * This function explicitly avoids any
 * floating point arithmetic. It also does
 * extra validation to ensure the resulting
 * Number will be 53 bits or less.
 * @param {String} value - BTC
 * @returns {Amount} Satoshis.
 * @throws on parse error
 */

Amount.satoshi = function satoshi(value) {
  if (utils.isInt(value))
    return value;

  return Amount.parse(value, 8, false);
};

/**
 * Safely convert a BTC string to satoshis.
 * This function explicitly avoids any
 * floating point arithmetic. It also does
 * extra validation to ensure the resulting
 * Number will be 53 bits or less.
 * @param {String} value - BTC
 * @returns {Amount} Satoshis.
 * @throws on parse error
 */

Amount.parse = function parse(value, dec, num) {
  var negative = false;
  var mult = Math.pow(10, dec);
  var maxLo = utils.MAX_SAFE_INTEGER % mult;
  var maxHi = (utils.MAX_SAFE_INTEGER - maxLo) / mult;
  var parts, hi, lo, result;

  if (num && typeof value === 'number') {
    assert(utils.isNumber(value), 'Non-BTC value for conversion.');
    value = value.toString(10);
  }

  assert(utils.isFloat(value), 'Non-BTC value for conversion.');

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

/*
 * Expose
 */

module.exports = Amount;
