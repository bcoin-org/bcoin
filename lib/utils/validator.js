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
 * Test whether a config option is present.
 * @param {String} key
 * @returns {Boolean}
 */

Validator.prototype.init = function init(data) {
  var i, obj;

  assert(data && typeof data === 'object');

  if (!Array.isArray(data))
    data = [data];

  for (i = 0; i < data.length; i++) {
    obj = data[i];
    assert(obj && typeof obj === 'object');
    this.data.push(obj);
  }
};

/**
 * Test whether a config option is present.
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
 * Get a config option.
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
    value = map[key];
    if (value != null)
      return value;
  }

  return fallback;
};

/**
 * Get a config option (as a string).
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
    throw new Error(key + ' must be a string.');

  return value;
};

/**
 * Get a config option (as a number).
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
      throw new Error(key + ' must be a number.');
    return value;
  }

  if (!/^\d+$/.test(value))
    throw new Error(key + ' must be a number.');

  value = parseInt(value, 10);

  if (!isFinite(value))
    throw new Error(key + ' must be a number.');

  return value;
};

/**
 * Get a config option (as a number).
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
      throw new Error(key + ' must be a number.');
    return value;
  }

  if (!/^\d+(\.\d{0,8})?$/.test(value))
    throw new Error(key + ' must be a number.');

  value = parseFloat(value);

  if (!isFinite(value))
    throw new Error(key + ' must be a number.');

  return value * 1e8;
};

/**
 * Get a config option (as a number).
 * @param {String} key
 * @param {Object?} fallback
 * @returns {Number|null}
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
      throw new Error(key + ' must be a buffer.');
    if (value.length !== 32)
      throw new Error(key + ' must be a buffer.');
    return value.toString('hex');
  }

  if (value.length !== 64)
    throw new Error(key + ' must be a hex string.');

  if (!/^[0-9a-f]+$/i.test(value))
    throw new Error(key + ' must be a hex string.');

  for (i = 0; i < value.length; i += 2)
    out = value.slice(i, i + 2) + out;

  return out;
};

/**
 * Get a config option (as a number).
 * @param {String} key
 * @param {Object?} fallback
 * @returns {Number|null}
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
      throw new Error(key + ' must be a number or string.');
    return value;
  }

  num = parseInt(value, 10);

  if (!isFinite(num))
    return value;

  return num;
};

/**
 * Get a config option (as a boolean).
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
    assert(typeof value === 'boolean',
      'Passed in config option is of wrong type.');
    return value;
  }

  if (value === 'true' || value === '1')
    return true;

  if (value === 'false' || value === '0')
    return false;

  throw new Error(key + ' must be a boolean.');
};

/**
 * Get a config option (as a buffer).
 * @param {String} key
 * @param {Object?} fallback
 * @returns {Buffer|null}
 */

Validator.prototype.buf = function buf(key, fallback) {
  var value = this.get(key);
  var data;

  if (fallback === undefined)
    fallback = null;

  if (value === null)
    return fallback;

  if (typeof value !== 'string') {
    assert(Buffer.isBuffer(value),
      'Passed in config option is of wrong type.');
    return value;
  }

  data = new Buffer(value, 'hex');

  if (data.length !== value.length / 2)
    throw new Error(key + ' must be a hex string.');

  return data;
};

/**
 * Get a config option (as an array of strings).
 * @param {String} key
 * @param {Object?} fallback
 * @returns {String[]|null}
 */

Validator.prototype.array = function array(key, fallback) {
  var value = this.get(key);

  if (fallback === undefined)
    fallback = null;

  if (value === null)
    return fallback;

  if (typeof value !== 'string') {
    if (!Array.isArray(value))
      throw new Error(key + ' must be a list/array.');
    return value;
  }

  return value.trim().split(/\s*,\s*/);
};

/**
 * Get a config option (as an object).
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

  if (typeof value !== 'string') {
    if (!value || typeof value !== 'object')
      throw new Error(key + ' must be an object.');
    return value;
  }

  try {
    value = JSON.parse(value);
  } catch (e) {
    ;
  }

  if (!value || typeof value !== 'object')
    throw new Error(key + ' must be an object.');

  return value;
};

/**
 * Get a config option (as an object).
 * @param {String} key
 * @param {Object?} fallback
 * @returns {Object|null}
 */

Validator.prototype.next = function next(key, fallback) {
  var value = this.obj(key, fallback);

  if (fallback === undefined)
    fallback = null;

  if (value === null)
    return fallback;

  return new Validator(value);
};

/**
 * Get a config option (as a function).
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

  if (typeof value !== 'string') {
    if (typeof value !== 'function')
      throw new Error(key + ' must be a function.');
    return value;
  }

  throw new Error(key + ' must be a function.');
};

/*
 * Expose
 */

module.exports = Validator;
