'use strict';

var assert = require('assert');

/**
 * Validator
 * @alias module:utils.Validator
 * @constructor
 * @param {Object} options
 */

function Validator(data) {
  if (!(this instanceof Validator))
    return new Validator(data);

  this.data = [];

  if (data)
    this.init(data);
}

/**
 * Initialize the validator.
 * @private
 * @param {Object} data
 */

Validator.prototype.init = function init(data) {
  assert(data && typeof data === 'object');

  if (!Array.isArray(data))
    data = [data];

  this.data = data;
};

/**
 * Test whether value is present.
 * @param {String} key
 * @returns {Boolean}
 */

Validator.prototype.has = function has(key) {
  var i, map, value;

  assert(typeof key === 'string' || typeof key === 'number',
    'Key must be a string.');

  for (i = 0; i < this.data.length; i++) {
    map = this.data[i];
    value = map[key];
    if (value != null)
      return true;
  }

  return false;
};

/**
 * Get a value (no type validation).
 * @param {String} key
 * @param {Object?} fallback
 * @returns {Object|null}
 */

Validator.prototype.get = function get(key, fallback) {
  var i, keys, value, map;

  if (fallback === undefined)
    fallback = null;

  if (Array.isArray(key)) {
    keys = key;
    for (i = 0; i < keys.length; i++) {
      key = keys[i];
      value = this.get(key);
      if (value !== null)
        return value;
    }
    return fallback;
  }

  assert(typeof key === 'string' || typeof key === 'number',
    'Key must be a string.');

  for (i = 0; i < this.data.length; i++) {
    map = this.data[i];

    if (!map || typeof map !== 'object')
      throw new Error('Data is not an object.');

    value = map[key];

    if (value != null)
      return value;
  }

  return fallback;
};

/**
 * Get a value (as a string).
 * @param {String} key
 * @param {Object?} fallback
 * @returns {String|null}
 */

Validator.prototype.str = function str(key, fallback) {
  var value = this.get(key);

  if (fallback === undefined)
    fallback = null;

  if (value === null)
    return fallback;

  if (typeof value !== 'string')
    throw new Error(fmt(key) + ' must be a string.');

  return value;
};

/**
 * Get a value (as a number).
 * @param {String} key
 * @param {Object?} fallback
 * @returns {Number|null}
 */

Validator.prototype.num = function num(key, fallback) {
  var value = this.get(key);

  if (fallback === undefined)
    fallback = null;

  if (value === null)
    return fallback;

  if (typeof value !== 'string') {
    if (typeof value !== 'number')
      throw new Error(fmt(key) + ' must be a number.');
    return value;
  }

  if (!/^\d+$/.test(value))
    throw new Error(fmt(key) + ' must be a number.');

  value = parseInt(value, 10);

  if (!isFinite(value))
    throw new Error(fmt(key) + ' must be a number.');

  return value;
};

/**
 * Get a value (as a uint32).
 * @param {String} key
 * @param {Object?} fallback
 * @returns {Number|null}
 */

Validator.prototype.u32 = function u32(key, fallback) {
  var value = this.num(key);

  if (fallback === undefined)
    fallback = null;

  if (value === null)
    return fallback;

  if (value % 1 !== 0 || value < 0 || value > 0xffffffff)
    throw new Error(fmt(key) + ' must be a uint32.');

  return value;
};

/**
 * Get a value (as a uint64).
 * @param {String} key
 * @param {Object?} fallback
 * @returns {Number|null}
 */

Validator.prototype.u64 = function u64(key, fallback) {
  var value = this.num(key);

  if (fallback === undefined)
    fallback = null;

  if (value === null)
    return fallback;

  if (value % 1 !== 0 || value < 0 || value > 0x1fffffffffffff)
    throw new Error(fmt(key) + ' must be a uint64.');

  return value;
};

/**
 * Get a value (as a satoshi number or btc string).
 * @param {String} key
 * @param {Object?} fallback
 * @returns {Number|null}
 */

Validator.prototype.amt = function amt(key, fallback) {
  var value = this.get(key);

  if (fallback === undefined)
    fallback = null;

  if (value === null)
    return fallback;

  if (typeof value !== 'string') {
    if (typeof value !== 'number')
      throw new Error(fmt(key) + ' must be a number.');
    return value;
  }

  if (!/^\d+(\.\d{0,8})?$/.test(value))
    throw new Error(fmt(key) + ' must be a number.');

  value = parseFloat(value);

  if (!isFinite(value))
    throw new Error(fmt(key) + ' must be a number.');

  value *= 1e8;

  if (value % 1 !== 0 || value < 0 || value > 0x1fffffffffffff)
    throw new Error(fmt(key) + ' must be a uint64.');

  return value;
};

/**
 * Get a value (as a btc float).
 * @param {String} key
 * @param {Object?} fallback
 * @returns {Number|null}
 */

Validator.prototype.btc = function btc(key, fallback) {
  var value = this.num(key);

  if (fallback === undefined)
    fallback = null;

  if (value === null)
    return fallback;

  value *= 1e8;

  if (value % 1 !== 0 || value < 0 || value > 0x1fffffffffffff)
    throw new Error(fmt(key) + ' must be a uint64.');

  return value;
};

/**
 * Get a value (as a reverse hash).
 * @param {String} key
 * @param {Object?} fallback
 * @returns {Hash|null}
 */

Validator.prototype.hash = function hash(key, fallback) {
  var value = this.get(key);
  var out = '';
  var i;

  if (fallback === undefined)
    fallback = null;

  if (value === null)
    return fallback;

  if (typeof value !== 'string') {
    if (!Buffer.isBuffer(value))
      throw new Error(fmt(key) + ' must be a hash.');
    if (value.length !== 32)
      throw new Error(fmt(key) + ' must be a hash.');
    return value.toString('hex');
  }

  if (value.length !== 64)
    throw new Error(fmt(key) + ' must be a hex string.');

  if (!/^[0-9a-f]+$/i.test(value))
    throw new Error(fmt(key) + ' must be a hex string.');

  for (i = 0; i < value.length; i += 2)
    out = value.slice(i, i + 2) + out;

  return out;
};

/**
 * Get a value (as a number or reverse hash).
 * @param {String} key
 * @param {Object?} fallback
 * @returns {Number|Hash|null}
 */

Validator.prototype.numhash = function numhash(key, fallback) {
  var value = this.get(key);

  if (value === null)
    return fallback;

  if (typeof value === 'string')
    return this.hash(key);

  return this.num(key);
};

/**
 * Get a value (as a number or string).
 * @param {String} key
 * @param {Object?} fallback
 * @returns {Number|String|null}
 */

Validator.prototype.numstr = function numstr(key, fallback) {
  var value = this.get(key);
  var num;

  if (fallback === undefined)
    fallback = null;

  if (value === null)
    return fallback;

  if (typeof value !== 'string') {
    if (typeof value !== 'number')
      throw new Error(fmt(key) + ' must be a number or string.');
    return value;
  }

  num = parseInt(value, 10);

  if (!isFinite(num))
    return value;

  return num;
};

/**
 * Get a value (as a boolean).
 * @param {String} key
 * @param {Object?} fallback
 * @returns {Boolean|null}
 */

Validator.prototype.bool = function bool(key, fallback) {
  var value = this.get(key);

  if (fallback === undefined)
    fallback = null;

  if (value === null)
    return fallback;

  if (typeof value !== 'string') {
    if (typeof value !== 'boolean')
      throw new Error(fmt(key) + ' must be a boolean.');
    return value;
  }

  if (value === 'true' || value === '1')
    return true;

  if (value === 'false' || value === '0')
    return false;

  throw new Error(fmt(key) + ' must be a boolean.');
};

/**
 * Get a value (as a buffer).
 * @param {String} key
 * @param {Object?} fallback
 * @param {String?} enc
 * @returns {Buffer|null}
 */

Validator.prototype.buf = function buf(key, fallback, enc) {
  var value = this.get(key);
  var data;

  if (!enc)
    enc = 'hex';

  if (fallback === undefined)
    fallback = null;

  if (value === null)
    return fallback;

  if (typeof value !== 'string') {
    if (!Buffer.isBuffer(value))
      throw new Error(fmt(key) + ' must be a buffer.');
    return value;
  }

  data = new Buffer(value, enc);

  if (data.length !== Buffer.byteLength(value, enc))
    throw new Error(fmt(key) + ' must be a ' + enc + ' string.');

  return data;
};

/**
 * Get a value (as an array).
 * @param {String} key
 * @param {Object?} fallback
 * @returns {Array|String[]|null}
 */

Validator.prototype.array = function array(key, fallback) {
  var value = this.get(key);

  if (fallback === undefined)
    fallback = null;

  if (value === null)
    return fallback;

  if (typeof value !== 'string') {
    if (!Array.isArray(value))
      throw new Error(fmt(key) + ' must be a list/array.');
    return value;
  }

  return value.trim().split(/\s*,\s*/);
};

/**
 * Get a value (as an object).
 * @param {String} key
 * @param {Object?} fallback
 * @returns {Object|null}
 */

Validator.prototype.obj = function obj(key, fallback) {
  var value = this.get(key);

  if (fallback === undefined)
    fallback = null;

  if (value === null)
    return fallback;

  if (!value || typeof value !== 'object')
    throw new Error(fmt(key) + ' must be an object.');

  return value;
};

/**
 * Get a value (as a function).
 * @param {String} key
 * @param {Object?} fallback
 * @returns {Function|null}
 */

Validator.prototype.func = function func(key, fallback) {
  var value = this.get(key);

  if (fallback === undefined)
    fallback = null;

  if (value === null)
    return fallback;

  if (typeof value !== 'function')
    throw new Error(fmt(key) + ' must be a function.');

  return value;
};

/*
 * Helpers
 */

function fmt(key) {
  if (typeof key === 'number')
    return 'Param #' + key;
  return key;
}

/*
 * Expose
 */

module.exports = Validator;
