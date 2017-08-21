/*!
 * enforce.js - type enforcement for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const util = require('./util');

function enforce(value, name, type, func) {
  if (!value) {
    if (!func)
      func = enforce;

    if (name && !type)
      throwError(name, func);

    if (!name)
      name = 'value';

    throwError(`'${name}' must be a(n) ${type}.`, func);
  }
}

function throwError(msg, func) {
  const error = new TypeError(msg);
  if (Error.captureStackTrace && func)
    Error.captureStackTrace(error, func);
  throw error;
}

enforce.none = function none(value, name) {
  enforce(value == null, name, 'object', none);
};

enforce.nul = function nul(value, name) {
  enforce(value === null, name, 'object', nul);
};

enforce.undef = function undef(value, name) {
  enforce(value === undefined, name, 'object', undef);
};

enforce.str = function str(value, name) {
  enforce(typeof value === 'string', name, 'string', str);
};

enforce.bool = function bool(value, name) {
  enforce(typeof value === 'boolean', name, 'boolean', bool);
};

enforce.num = function num(value, name) {
  enforce(util.isNumber(value), name, 'number', num);
};

enforce.obj = function obj(v, name) {
  enforce(v && typeof v === 'object' && !Array.isArray(v), name, 'object', obj);
};

enforce.array = function array(value, name) {
  enforce(Array.isArray(value), name, 'object', array);
};

enforce.func = function func(value, name) {
  enforce(typeof value === 'function', name, 'function', func);
};

enforce.error = function error(value, name) {
  enforce(value instanceof Error, name, 'object', error);
};

enforce.regexp = function regexp(value, name) {
  enforce(value && typeof value.exec === 'function' , name, 'object', regexp);
};

enforce.buf = function buf(value, name) {
  enforce(Buffer.isBuffer(value), name, 'buffer', buf);
};

enforce.len = function len(value, length, name) {
  if ((typeof value !== 'string' && !value) || value.length !== length) {
    if (!name)
      name = 'value';
    throwError(`'${name}' must have a length of ${length}.`, len);
  }
};

enforce.instance = function instance(obj, parent, name) {
  if (!(obj instanceof parent)) {
    if (!name)
      name = 'value';
    throwError(`'${name}' must be an instance of ${parent.name}.`, instance);
  }
};

enforce.uint = function uint(value, name) {
  enforce(util.isUInt(value), name, 'uint', uint);
};

enforce.int = function int(value, name) {
  enforce(util.isInt(value), name, 'int', int);
};

enforce.u8 = function u8(value, name) {
  enforce(util.isU8(value), name, 'uint8', u8);
};

enforce.u16 = function u16(value, name) {
  enforce(util.isU16(value), name, 'uint16', u16);
};

enforce.u32 = function u32(value, name) {
  enforce(util.isU32(value), name, 'uint32', u32);
};

enforce.u64 = function u64(value, name) {
  enforce(util.isU64(value), name, 'uint64', u64);
};

enforce.i8 = function i8(value, name) {
  enforce(util.isI8(value), name, 'int8', i8);
};

enforce.i16 = function i16(value, name) {
  enforce(util.isI16(value), name, 'int16', i16);
};

enforce.i32 = function i32(value, name) {
  enforce(util.isI32(value), name, 'int32', i32);
};

enforce.i64 = function i64(value, name) {
  enforce(util.isI64(value), name, 'int64', i64);
};

enforce.ufloat = function ufloat(value, name) {
  enforce(util.isUfloat(value), name, 'positive float', ufloat);
};

enforce.float = function float(value, name) {
  enforce(util.isFloat(value), name, 'float', float);
};

enforce.ascii = function ascii(value, name) {
  enforce(util.isAscii(value), name, 'ascii string', ascii);
};

enforce.hex = function hex(value, name) {
  enforce(util.isHex(value), name, 'hex string', hex);
};

enforce.hex160 = function hex160(value, name) {
  enforce(util.isHex160(value), name, '160 bit hex string', hex160);
};

enforce.hex256 = function hex256(value, name) {
  enforce(util.isHex256(value), name, '256 bit hex string', hex256);
};

enforce.base58 = function base58(value, name) {
  enforce(util.isBase58(value), name, 'base58 string', base58);
};

module.exports = enforce;
