/*!
 * validator.js - validator for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');

/**
 * Validator
 */

class Validator {
  /**
   * Create a validator.
   * @constructor
   * @param {Object} map
   * @param {Boolean} [loose=false]
   */

  constructor(map, loose) {
    if (!map || typeof map !== 'object')
      throw new ValidationError('map', 'object');

    this.map = map;
    this.loose = loose || false;
  }

  /**
   * Create a multi validator.
   * @param {Object[]} maps
   * @param {Boolean} [loose=false]
   * @returns {MultiValidator}
   */

  static multi(maps, loose) {
    return new MultiValidator(maps, loose);
  }

  /**
   * Create a multi validator from an http request.
   * @param {Object} req
   * @returns {MultiValidator}
   */

  static fromRequest(req) {
    const query = new Validator(req.query, true);
    const params = new Validator(req.params, true);
    const body = new Validator(req.body, false);
    return new MultiValidator([query, params, body]);
  }

  /**
   * Create a child validator.
   * @param {String} key
   * @returns {Validator}
   */

  child(key) {
    return new this.constructor(this.get(key));
  }

  /**
   * Test whether value is present.
   * @param {String} key
   * @returns {Boolean}
   */

  has(key) {
    return this.get(key) != null;
  }

  /**
   * Get a value (no type validation).
   * @param {String} key
   * @param {Object?} fallback
   * @returns {Object|null}
   */

  get(key, fallback) {
    if (fallback === undefined)
      fallback = null;

    if (Array.isArray(key)) {
      const keys = key;
      for (const key of keys) {
        const value = this.get(key);
        if (value !== null)
          return value;
      }
      return fallback;
    }

    assert(typeof key === 'string' || typeof key === 'number',
      'Key must be a string or number.');

    const value = this.map[key];

    if (value != null)
      return value;

    return fallback;
  }

  /**
   * Get a value's type.
   * @param {String} key
   * @returns {String}
   */

  typeOf(key) {
    const value = this.get(key);

    if (value == null)
      return 'null';

    return typeof value;
  }

  /**
   * Get a value (as a string).
   * @param {String} key
   * @param {Object?} fallback
   * @returns {String|null}
   */

  str(key, fallback) {
    const value = this.get(key);

    if (fallback === undefined)
      fallback = null;

    if (value === null)
      return fallback;

    if (typeof value !== 'string')
      throw new ValidationError(key, 'string');

    return value;
  }

  /**
   * Get a value (as an integer).
   * @param {String} key
   * @param {Object?} fallback
   * @returns {Number|null}
   */

  int(key, fallback) {
    const value = this.get(key);

    if (fallback === undefined)
      fallback = null;

    if (value === null)
      return fallback;

    if (typeof value !== 'string') {
      if (typeof value !== 'number')
        throw new ValidationError(key, 'int');

      if (!Number.isSafeInteger(value))
        throw new ValidationError(key, 'int');

      return value;
    }

    if (!this.loose)
      throw new ValidationError(key, 'int');

    if (!/^\-?\d+$/.test(value))
      throw new ValidationError(key, 'int');

    const num = parseInt(value, 10);

    if (!Number.isSafeInteger(num))
      throw new ValidationError(key, 'int');

    return num;
  }

  /**
   * Get a value (as a signed integer).
   * @param {String} key
   * @param {Object?} fallback
   * @returns {Number|null}
   */

  uint(key, fallback) {
    const value = this.int(key);

    if (fallback === undefined)
      fallback = null;

    if (value === null)
      return fallback;

    if (value < 0)
      throw new ValidationError(key, 'uint');

    return value;
  }

  /**
   * Get a value (as a float).
   * @param {String} key
   * @param {Object?} fallback
   * @returns {Number|null}
   */

  float(key, fallback) {
    const value = this.get(key);

    if (fallback === undefined)
      fallback = null;

    if (value === null)
      return fallback;

    if (typeof value !== 'string') {
      if (typeof value !== 'number')
        throw new ValidationError(key, 'float');

      if (!isFinite(value))
        throw new ValidationError(key, 'float');

      return value;
    }

    if (!this.loose)
      throw new ValidationError(key, 'float');

    if (!/^\-?\d*(?:\.\d*)?$/.test(value))
      throw new ValidationError(key, 'float');

    if (!/\d/.test(value))
      throw new ValidationError(key, 'float');

    const num = parseFloat(value);

    if (!isFinite(num))
      throw new ValidationError(key, 'float');

    return num;
  }

  /**
   * Get a value (as a positive float).
   * @param {String} key
   * @param {Object?} fallback
   * @returns {Number|null}
   */

  ufloat(key, fallback) {
    const value = this.float(key);

    if (fallback === undefined)
      fallback = null;

    if (value === null)
      return fallback;

    if (value < 0)
      throw new ValidationError(key, 'positive float');

    return value;
  }

  /**
   * Get a value (as a fixed number).
   * @param {String} key
   * @param {Number?} exp
   * @param {Object?} fallback
   * @returns {Number|null}
   */

  fixed(key, exp, fallback) {
    const value = this.float(key);

    if (fallback === undefined)
      fallback = null;

    if (value === null)
      return fallback;

    try {
      return fromFloat(value, exp || 0);
    } catch (e) {
      throw new ValidationError(key, 'fixed number');
    }
  }

  /**
   * Get a value (as a positive fixed number).
   * @param {String} key
   * @param {Number?} exp
   * @param {Object?} fallback
   * @returns {Number|null}
   */

  ufixed(key, exp, fallback) {
    const value = this.fixed(key, exp);

    if (fallback === undefined)
      fallback = null;

    if (value === null)
      return fallback;

    if (value < 0)
      throw new ValidationError(key, 'positive fixed number');

    return value;
  }

  /**
   * Get a value (as an int32).
   * @param {String} key
   * @param {Object?} fallback
   * @returns {Number|null}
   */

  i8(key, fallback) {
    const value = this.int(key);

    if (fallback === undefined)
      fallback = null;

    if (value === null)
      return fallback;

    if (value < -0x80 || value > 0x7f)
      throw new ValidationError(key, 'i8');

    return value;
  }

  /**
   * Get a value (as an int32).
   * @param {String} key
   * @param {Object?} fallback
   * @returns {Number|null}
   */

  i16(key, fallback) {
    const value = this.int(key);

    if (fallback === undefined)
      fallback = null;

    if (value === null)
      return fallback;

    if (value < -0x8000 || value > 0x7fff)
      throw new ValidationError(key, 'i16');

    return value;
  }

  /**
   * Get a value (as an int32).
   * @param {String} key
   * @param {Object?} fallback
   * @returns {Number|null}
   */

  i32(key, fallback) {
    const value = this.int(key);

    if (fallback === undefined)
      fallback = null;

    if (value === null)
      return fallback;

    if ((value | 0) !== value)
      throw new ValidationError(key, 'int32');

    return value;
  }

  /**
   * Get a value (as an int64).
   * @param {String} key
   * @param {Object?} fallback
   * @returns {Number|null}
   */

  i64(key, fallback) {
    return this.int(key, fallback);
  }

  /**
   * Get a value (as a uint32).
   * @param {String} key
   * @param {Object?} fallback
   * @returns {Number|null}
   */

  u8(key, fallback) {
    const value = this.uint(key);

    if (fallback === undefined)
      fallback = null;

    if (value === null)
      return fallback;

    if ((value & 0xff) !== value)
      throw new ValidationError(key, 'uint8');

    return value;
  }

  /**
   * Get a value (as a uint16).
   * @param {String} key
   * @param {Object?} fallback
   * @returns {Number|null}
   */

  u16(key, fallback) {
    const value = this.uint(key);

    if (fallback === undefined)
      fallback = null;

    if (value === null)
      return fallback;

    if ((value & 0xffff) !== value)
      throw new ValidationError(key, 'uint16');

    return value;
  }

  /**
   * Get a value (as a uint32).
   * @param {String} key
   * @param {Object?} fallback
   * @returns {Number|null}
   */

  u32(key, fallback) {
    const value = this.uint(key);

    if (fallback === undefined)
      fallback = null;

    if (value === null)
      return fallback;

    if ((value >>> 0) !== value)
      throw new ValidationError(key, 'uint32');

    return value;
  }

  /**
   * Get a value (as a uint64).
   * @param {String} key
   * @param {Object?} fallback
   * @returns {Number|null}
   */

  u64(key, fallback) {
    return this.uint(key, fallback);
  }

  /**
   * Get a value (as a reverse hash).
   * @param {String} key
   * @param {Object?} fallback
   * @returns {Hash|null}
   */

  hash(key, fallback) {
    const value = this.get(key);

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

    return value.toLowerCase();
  }

  /**
   * Get a value (as a reverse hash).
   * @param {String} key
   * @param {Object?} fallback
   * @returns {Buffer|null}
   */

  bhash(key, fallback) {
    const value = this.hash(key, fallback);

    if (!value)
      return value;

    return Buffer.from(value, 'hex');
  }

  /**
   * Get a value (as a number or hash).
   * @param {String} key
   * @param {Object?} fallback
   * @returns {Number|Hash|null}
   */

  uinthash(key, fallback) {
    const value = this.get(key);

    if (fallback == null)
      fallback = null;

    if (value == null)
      return fallback;

    if (Buffer.isBuffer(value))
      return this.hash(key, fallback);

    if (typeof value === 'string') {
      if (!this.loose || value.length === 64)
        return this.hash(key, fallback);
    }

    return this.uint(key, fallback);
  }

  /**
   * Get a value (as a number or hash).
   * @param {String} key
   * @param {Object?} fallback
   * @returns {Number|Buffer|null}
   */

  uintbhash(key, fallback) {
    const value = this.uinthash(key, fallback);

    if (typeof value !== 'string')
      return value;

    return Buffer.from(value, 'hex');
  }

  /**
   * Get a value (as a reverse hash).
   * @param {String} key
   * @param {Object?} fallback
   * @returns {Hash|null}
   */

  rhash(key, fallback) {
    const value = this.get(key);

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

    let out = '';

    for (let i = 0; i < value.length; i += 2)
      out = value.slice(i, i + 2) + out;

    return out.toLowerCase();
  }

  /**
   * Get a value (as a reverse hash).
   * @param {String} key
   * @param {Object?} fallback
   * @returns {Buffer|null}
   */

  brhash(key, fallback) {
    const value = this.rhash(key, fallback);

    if (!value)
      return value;

    return Buffer.from(value, 'hex');
  }

  /**
   * Get a value (as a number or reverse hash).
   * @param {String} key
   * @param {Object?} fallback
   * @returns {Number|Hash|null}
   */

  uintrhash(key, fallback) {
    const value = this.get(key);

    if (fallback == null)
      fallback = null;

    if (value == null)
      return fallback;

    if (Buffer.isBuffer(value))
      return this.rhash(key, fallback);

    if (typeof value === 'string') {
      if (!this.loose || value.length === 64)
        return this.rhash(key, fallback);
    }

    return this.uint(key, fallback);
  }

  /**
   * Get a value (as a number or reverse hash).
   * @param {String} key
   * @param {Object?} fallback
   * @returns {Number|Buffer|null}
   */

  uintbrhash(key, fallback) {
    const value = this.uintrhash(key, fallback);

    if (typeof value !== 'string')
      return value;

    return Buffer.from(value, 'hex');
  }

  /**
   * Get a value (as a boolean).
   * @param {String} key
   * @param {Object?} fallback
   * @returns {Boolean|null}
   */

  bool(key, fallback) {
    const value = this.get(key);

    if (fallback === undefined)
      fallback = null;

    if (value === null)
      return fallback;

    // Bitcoin Core compat.
    if (typeof value === 'number') {
      if (value === 1)
        return true;

      if (value === 0)
        return false;
    }

    if (typeof value !== 'string') {
      if (typeof value !== 'boolean')
        throw new ValidationError(key, 'boolean');
      return value;
    }

    if (!this.loose)
      throw new ValidationError(key, 'boolean');

    if (value === 'true' || value === '1')
      return true;

    if (value === 'false' || value === '0')
      return false;

    throw new ValidationError(key, 'boolean');
  }

  /**
   * Get a value (as a buffer).
   * @param {String} key
   * @param {Object?} fallback
   * @param {String?} enc
   * @returns {Buffer|null}
   */

  buf(key, fallback, enc) {
    const value = this.get(key);

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

    const data = Buffer.from(value, enc);

    if (data.length !== Buffer.byteLength(value, enc))
      throw new ValidationError(key, `${enc} string`);

    return data;
  }

  /**
   * Get a value (as an array).
   * @param {String} key
   * @param {Object?} fallback
   * @returns {Array|String[]|null}
   */

  array(key, fallback) {
    const value = this.get(key);

    if (fallback === undefined)
      fallback = null;

    if (value === null)
      return fallback;

    if (typeof value !== 'string') {
      if (!Array.isArray(value))
        throw new ValidationError(key, 'array');
      return value;
    }

    if (!this.loose)
      throw new ValidationError(key, 'array');

    const parts = value.trim().split(/\s*,\s*/);
    const result = [];

    for (const part of parts) {
      if (part.length === 0)
        continue;

      result.push(part);
    }

    return result;
  }

  /**
   * Get a value (as an object).
   * @param {String} key
   * @param {Object?} fallback
   * @returns {Object|null}
   */

  obj(key, fallback) {
    const value = this.get(key);

    if (fallback === undefined)
      fallback = null;

    if (value === null)
      return fallback;

    if (typeof value !== 'object' || Array.isArray(value))
      throw new ValidationError(key, 'object');

    return value;
  }

  /**
   * Get a value (as a function).
   * @param {String} key
   * @param {Object?} fallback
   * @returns {Function|null}
   */

  func(key, fallback) {
    const value = this.get(key);

    if (fallback === undefined)
      fallback = null;

    if (value === null)
      return fallback;

    if (typeof value !== 'function')
      throw new ValidationError(key, 'function');

    return value;
  }
}

/*
 * Constants
 */

const SENTINEL = new Validator(Object.create(null));

/**
 * Multi Validator
 * @extends Validator
 */

class MultiValidator {
  /**
   * Create a multi validator.
   * @constructor
   * @param {Object[]} maps
   * @param {Boolean} [loose=false]
   */

  constructor(maps, loose) {
    this.maps = [];

    this.init(maps, loose);
  }

  /**
   * Initialize the validator.
   * @private
   * @param {Object[]} maps
   * @param {Boolean} [loose=false]
   */

  init(maps, loose) {
    assert(Array.isArray(maps));
    assert(maps.length > 0);

    for (const map of maps) {
      if (!(map instanceof Validator)) {
        assert(map && typeof map === 'object');
        this.maps.push(new Validator(map, loose));
        continue;
      }
      this.maps.push(map);
    }
  }

  /**
   * Get a validator.
   * @private
   * @param {String} key
   * @returns {Validator}
   */

  find(key) {
    for (const map of this.maps) {
      if (map.has(key))
        return map;
    }
    return SENTINEL;
  }

  child(key) {
    return this.find(key).child(key);
  }

  has(key) {
    return this.find(key).has(key);
  }

  get(key, fallback) {
    return this.find(key).get(key, fallback);
  }

  typeOf(key) {
    return this.find(key).typeOf(key);
  }

  str(key, fallback) {
    return this.find(key).str(key, fallback);
  }

  int(key, fallback) {
    return this.find(key).int(key, fallback);
  }

  uint(key, fallback) {
    return this.find(key).uint(key, fallback);
  }

  float(key, fallback) {
    return this.find(key).float(key, fallback);
  }

  ufloat(key, fallback) {
    return this.find(key).ufloat(key, fallback);
  }

  fixed(key, exp, fallback) {
    return this.find(key).fixed(key, exp, fallback);
  }

  ufixed(key, exp, fallback) {
    return this.find(key).ufixed(key, exp, fallback);
  }

  i8(key, fallback) {
    return this.find(key).i8(key, fallback);
  }

  i16(key, fallback) {
    return this.find(key).i16(key, fallback);
  }

  i32(key, fallback) {
    return this.find(key).i32(key, fallback);
  }

  i64(key, fallback) {
    return this.find(key).i64(key, fallback);
  }

  u8(key, fallback) {
    return this.find(key).u8(key, fallback);
  }

  u16(key, fallback) {
    return this.find(key).u16(key, fallback);
  }

  u32(key, fallback) {
    return this.find(key).u32(key, fallback);
  }

  u64(key, fallback) {
    return this.find(key).u64(key, fallback);
  }

  hash(key, fallback) {
    return this.find(key).hash(key, fallback);
  }

  bhash(key, fallback) {
    return this.find(key).bhash(key, fallback);
  }

  uinthash(key, fallback) {
    return this.find(key).uinthash(key, fallback);
  }

  uintbhash(key, fallback) {
    return this.find(key).uintbhash(key, fallback);
  }

  rhash(key, fallback) {
    return this.find(key).rhash(key, fallback);
  }

  brhash(key, fallback) {
    return this.find(key).brhash(key, fallback);
  }

  uintrhash(key, fallback) {
    return this.find(key).uintrhash(key, fallback);
  }

  uintbrhash(key, fallback) {
    return this.find(key).uintbrhash(key, fallback);
  }

  bool(key, fallback) {
    return this.find(key).bool(key, fallback);
  }

  buf(key, fallback, enc) {
    return this.find(key).buf(key, fallback, enc);
  }

  array(key, fallback) {
    return this.find(key).array(key, fallback);
  }

  obj(key, fallback) {
    return this.find(key).obj(key, fallback);
  }

  func(key, fallback) {
    return this.find(key).func(key, fallback);
  }
}

/*
 * Helpers
 */

function fmt(key) {
  if (Array.isArray(key))
    key = key[0];

  if (typeof key === 'number')
    return `Param #${key}`;

  return key;
}

class ValidationError extends Error {
  constructor(key, type) {
    super();

    this.type = 'ValidationError';
    this.message = `${fmt(key)} must be a ${type}.`;

    if (Error.captureStackTrace)
      Error.captureStackTrace(this, ValidationError);
  }
}

function fromFloat(num, exp) {
  assert(typeof num === 'number' && isFinite(num));
  assert(Number.isSafeInteger(exp));

  let str = num.toFixed(exp);
  let sign = 1;

  if (str.length > 0 && str[0] === '-') {
    str = str.substring(1);
    sign = -1;
  }

  let hi = str;
  let lo = '0';

  const index = str.indexOf('.');

  if (index !== -1) {
    hi = str.substring(0, index);
    lo = str.substring(index + 1);
  }

  hi = hi.replace(/^0+/, '');
  lo = lo.replace(/0+$/, '');

  assert(hi.length <= 16 - exp,
    'Fixed number string exceeds 2^53-1.');

  assert(lo.length <= exp,
    'Too many decimal places in fixed number string.');

  if (hi.length === 0)
    hi = '0';

  while (lo.length < exp)
    lo += '0';

  if (lo.length === 0)
    lo = '0';

  assert(/^\d+$/.test(hi) && /^\d+$/.test(lo),
    'Non-numeric characters in fixed number string.');

  hi = parseInt(hi, 10);
  lo = parseInt(lo, 10);

  const mult = Math.pow(10, exp);
  const maxLo = Number.MAX_SAFE_INTEGER % mult;
  const maxHi = (Number.MAX_SAFE_INTEGER - maxLo) / mult;

  assert(hi < maxHi || (hi === maxHi && lo <= maxLo),
    'Fixed number string exceeds 2^53-1.');

  return sign * (hi * mult + lo);
}

/*
 * Expose
 */

module.exports = Validator;
