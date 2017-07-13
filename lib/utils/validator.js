/*!
 * validator.js - validator for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');

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
  assert(typeof key === 'string' || typeof key === 'number',
    'Key must be a string.');

  for (let map of this.data) {
    let value = map[key];
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
  if (fallback === undefined)
    fallback = null;

  if (Array.isArray(key)) {
    let keys = key;
    for (let key of keys) {
      let value = this.get(key);
      if (value !== null)
        return value;
    }
    return fallback;
  }

  assert(typeof key === 'string' || typeof key === 'number',
    'Key must be a string.');

  for (let map of this.data) {
    let value;

    if (!map || typeof map !== 'object')
      throw new ValidationError('data', 'object');

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
  let value = this.get(key);

  if (fallback === undefined)
    fallback = null;

  if (value === null)
    return fallback;

  if (typeof value !== 'string')
    throw new ValidationError(key, 'number');

  return value;
};

/**
 * Get a value (as a number).
 * @param {String} key
 * @param {Object?} fallback
 * @returns {Number|null}
 */

Validator.prototype.num = function num(key, fallback) {
  let value = this.get(key);

  if (fallback === undefined)
    fallback = null;

  if (value === null)
    return fallback;

  if (typeof value !== 'string') {
    if (typeof value !== 'number')
      throw new ValidationError(key, 'number');
    return value;
  }

  if (!/^\d+$/.test(value))
    throw new ValidationError(key, 'number');

  value = parseInt(value, 10);

  if (!isFinite(value))
    throw new ValidationError(key, 'number');

  return value;
};

/**
 * Get a value (as a number).
 * @param {String} key
 * @param {Object?} fallback
 * @returns {Number|null}
 */

Validator.prototype.flt = function flt(key, fallback) {
  let value = this.get(key);

  if (fallback === undefined)
    fallback = null;

  if (value === null)
    return fallback;

  if (typeof value !== 'string') {
    if (typeof value !== 'number')
      throw new ValidationError(key, 'float');
    return value;
  }

  if (!/^\d*(?:\.\d*)?$/.test(value))
    throw new ValidationError(key, 'float');

  value = parseFloat(value);

  if (!isFinite(value))
    throw new ValidationError(key, 'float');

  return value;
};

/**
 * Get a value (as a uint32).
 * @param {String} key
 * @param {Object?} fallback
 * @returns {Number|null}
 */

Validator.prototype.u32 = function u32(key, fallback) {
  let value = this.num(key);

  if (fallback === undefined)
    fallback = null;

  if (value === null)
    return fallback;

  if ((value >>> 0) !== value)
    throw new ValidationError(key, 'uint32');

  return value;
};

/**
 * Get a value (as a uint64).
 * @param {String} key
 * @param {Object?} fallback
 * @returns {Number|null}
 */

Validator.prototype.u64 = function u64(key, fallback) {
  let value = this.num(key);

  if (fallback === undefined)
    fallback = null;

  if (value === null)
    return fallback;

  if (value % 1 !== 0 || value < 0 || value > 0x1fffffffffffff)
    throw new ValidationError(key, 'uint64');

  return value;
};

/**
 * Get a value (as an int32).
 * @param {String} key
 * @param {Object?} fallback
 * @returns {Number|null}
 */

Validator.prototype.i32 = function i32(key, fallback) {
  let value = this.num(key);

  if (fallback === undefined)
    fallback = null;

  if (value === null)
    return fallback;

  if ((value | 0) !== value)
    throw new ValidationError(key, 'int32');

  return value;
};

/**
 * Get a value (as an int64).
 * @param {String} key
 * @param {Object?} fallback
 * @returns {Number|null}
 */

Validator.prototype.i64 = function i64(key, fallback) {
  let value = this.num(key);

  if (fallback === undefined)
    fallback = null;

  if (value === null)
    return fallback;

  if (value % 1 !== 0 || Math.abs(value) > 0x1fffffffffffff)
    throw new ValidationError(key, 'int64');

  return value;
};

/**
 * Get a value (as a satoshi number or btc string).
 * @param {String} key
 * @param {Object?} fallback
 * @returns {Number|null}
 */

Validator.prototype.amt = function amt(key, fallback) {
  let value = this.get(key);

  if (fallback === undefined)
    fallback = null;

  if (value === null)
    return fallback;

  if (typeof value !== 'string') {
    if (typeof value !== 'number')
      throw new ValidationError(key, 'amount');
    return value;
  }

  if (!/^\d+(\.\d{0,8})?$/.test(value))
    throw new ValidationError(key, 'amount');

  value = parseFloat(value);

  if (!isFinite(value))
    throw new ValidationError(key, 'amount');

  value *= 1e8;

  if (value % 1 !== 0 || value < 0 || value > 0x1fffffffffffff)
    throw new ValidationError(key, 'amount (uint64)');

  return value;
};

/**
 * Get a value (as a btc float).
 * @param {String} key
 * @param {Object?} fallback
 * @returns {Number|null}
 */

Validator.prototype.btc = function btc(key, fallback) {
  let value = this.num(key);

  if (fallback === undefined)
    fallback = null;

  if (value === null)
    return fallback;

  value *= 1e8;

  if (value % 1 !== 0 || value < 0 || value > 0x1fffffffffffff)
    throw new ValidationError(key, 'btc float (uint64)');

  return value;
};

/**
 * Get a value (as a reverse hash).
 * @param {String} key
 * @param {Object?} fallback
 * @returns {Hash|null}
 */

Validator.prototype.hash = function hash(key, fallback) {
  let value = this.get(key);
  let out = '';

  if (fallback === undefined)
    fallback = null;

  if (value === null)
    return fallback;

  if (typeof value !== 'string') {
    if (!Buffer.isBuffer(value))
      throw new ValidationError(key, 'hash');

    if (value.length !== 32)
      throw new ValidationError(key, 'hash');

    return value.toString('hex');
  }

  if (value.length !== 64)
    throw new ValidationError(key, 'hex string');

  if (!/^[0-9a-f]+$/i.test(value))
    throw new ValidationError(key, 'hex string');

  for (let i = 0; i < value.length; i += 2)
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
  let value = this.get(key);

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
  let value = this.get(key);
  let num;

  if (fallback === undefined)
    fallback = null;

  if (value === null)
    return fallback;

  if (typeof value !== 'string') {
    if (typeof value !== 'number')
      throw new ValidationError(key, 'number or string');
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
  let value = this.get(key);

  if (fallback === undefined)
    fallback = null;

  if (value === null)
    return fallback;

  // bitcoin core mixes semantics of truthiness amoung rpc methods
  // most "verbose" parameters are bools, but getrawtransaction is 1/0
  if (value === 1)
    return true;

  if (value === 0)
    return false;

  if (typeof value !== 'string') {
    if (typeof value !== 'boolean')
      throw new ValidationError(key, 'boolean');
    return value;
  }

  if (value === 'true' || value === '1')
    return true;

  if (value === 'false' || value === '0')
    return false;

  throw new ValidationError(key, 'boolean');
};

/**
 * Get a value (as a buffer).
 * @param {String} key
 * @param {Object?} fallback
 * @param {String?} enc
 * @returns {Buffer|null}
 */

Validator.prototype.buf = function buf(key, fallback, enc) {
  let value = this.get(key);
  let data;

  if (!enc)
    enc = 'hex';

  if (fallback === undefined)
    fallback = null;

  if (value === null)
    return fallback;

  if (typeof value !== 'string') {
    if (!Buffer.isBuffer(value))
      throw new ValidationError(key, 'buffer');
    return value;
  }

  data = Buffer.from(value, enc);

  if (data.length !== Buffer.byteLength(value, enc))
    throw new ValidationError(key, `${enc} string`);

  return data;
};

/**
 * Get a value (as an array).
 * @param {String} key
 * @param {Object?} fallback
 * @returns {Array|String[]|null}
 */

Validator.prototype.array = function array(key, fallback) {
  let value = this.get(key);
  let result, parts;

  if (fallback === undefined)
    fallback = null;

  if (value === null)
    return fallback;

  if (typeof value !== 'string') {
    if (!Array.isArray(value))
      throw new ValidationError(key, 'list/array');
    return value;
  }

  parts = value.trim().split(/\s*,\s*/);
  result = [];

  for (let part of parts) {
    if (part.length === 0)
      continue;

    result.push(part);
  }

  return result;
};

/**
 * Get a value (as an object).
 * @param {String} key
 * @param {Object?} fallback
 * @returns {Object|null}
 */

Validator.prototype.obj = function obj(key, fallback) {
  let value = this.get(key);

  if (fallback === undefined)
    fallback = null;

  if (value === null)
    return fallback;

  if (!value || typeof value !== 'object')
    throw new ValidationError(key, 'object');

  return value;
};

/**
 * Get a value (as a function).
 * @param {String} key
 * @param {Object?} fallback
 * @returns {Function|null}
 */

Validator.prototype.func = function func(key, fallback) {
  let value = this.get(key);

  if (fallback === undefined)
    fallback = null;

  if (value === null)
    return fallback;

  if (typeof value !== 'function')
    throw new ValidationError(key, 'function');

  return value;
};

/*
 * Helpers
 */

function fmt(key) {
  if (typeof key === 'number')
    return `Param #${key}`;
  return key;
}

function inherits(child, parent) {
  child.super_ = parent;
  Object.setPrototypeOf(child.prototype, parent.prototype);
  Object.defineProperty(child.prototype, 'constructor', {
    value: child,
    enumerable: false
  });
}

function ValidationError(key, type) {
  if (!(this instanceof ValidationError))
    return new ValidationError(key, type);

  Error.call(this);

  this.type = 'ValidationError';
  this.message = `${fmt(key)} must be a ${type}.`;

  if (Error.captureStackTrace)
    Error.captureStackTrace(this, ValidationError);
}

inherits(ValidationError, Error);

/*
 * Expose
 */

exports = Validator;
exports.Validator = Validator;
exports.Error = ValidationError;

module.exports = exports;
