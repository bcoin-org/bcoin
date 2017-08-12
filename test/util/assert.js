'use strict';

const _assert = require('assert');
const util = require('util');

const assert = function assert(value, message) {
  if (!value) {
    throw new assert.AssertionError({
      message,
      actual: value,
      expected: true,
      operator: '==',
      stackStartFunction: assert
    });
  }
};

Object.setPrototypeOf(assert, _assert);

assert.typeOf = function typeOf(value, expected, message) {
  _isString(expected, '`expected` must be a string.', typeOf);

  const actual = _typeOf(value);

  if (actual !== expected) {
    throw new assert.AssertionError({
      message,
      actual,
      expected,
      operator: 'typeof ==',
      stackStartFunction: typeOf
    });
  }
};

assert.notTypeOf = function notTypeOf(value, expected, message) {
  _isString(expected, '`expected` must be a string.', notTypeOf);

  const actual = _typeOf(value);

  if (actual === expected) {
    throw new assert.AssertionError({
      message,
      actual,
      expected,
      operator: 'typeof !=',
      stackStartFunction: notTypeOf
    });
  }
};

assert.instanceOf = function instanceOf(object, parent, message) {
  _isFunction(parent, '`parent` must be a constructor.', instanceOf);

  if (!(object instanceof parent)) {
    throw new assert.AssertionError({
      message,
      actual: _getConstructorName(object),
      expected: _getFunctionName(parent),
      operator: 'instanceof',
      stackStartFunction: instanceOf
    });
  }
};

assert.notInstanceOf = function notInstanceOf(object, parent, message) {
  _isFunction(parent, '`parent` must be a constructor.', notInstanceOf);

  if (object instanceof parent) {
    throw new assert.AssertionError({
      message,
      actual: _getConstructorName(object),
      expected: _getFunctionName(parent),
      operator: 'not instanceof',
      stackStartFunction: notInstanceOf
    });
  }
};

assert.bufferEqual = function bufferEqual(actual, expected, message) {
  _isBuffer(actual, '`actual` must be a buffer.', bufferEqual);
  _isBuffer(expected, '`expected` must be a buffer.', bufferEqual);

  if (actual !== expected && !actual.equals(expected)) {
    throw new assert.AssertionError({
      message,
      actual: actual.toString('hex'),
      expected: expected.toString('hex'),
      operator: '===',
      stackStartFunction: bufferEqual
    });
  }
};

assert.notBufferEqual = function notBufferEqual(actual, expected, message) {
  _isBuffer(actual, '`actual` must be a buffer.', notBufferEqual);
  _isBuffer(expected, '`expected` must be a buffer.', notBufferEqual);

  if (actual === expected || actual.equals(expected)) {
    throw new assert.AssertionError({
      message,
      actual: actual.toString('hex'),
      expected: expected.toString('hex'),
      operator: '!==',
      stackStartFunction: notBufferEqual
    });
  }
};

function _isString(value, message, stackStartFunction) {
  if (typeof value !== 'string') {
    throw new assert.AssertionError({
      message,
      actual: _typeOf(value),
      expected: 'string',
      operator: 'typeof ==',
      stackStartFunction
    });
  }
}

function _isFunction(value, message, stackStartFunction) {
  if (typeof value !== 'function') {
    throw new assert.AssertionError({
      message,
      actual: _typeOf(value),
      expected: 'function',
      operator: 'typeof ==',
      stackStartFunction
    });
  }
}

function _isBuffer(value, message, stackStartFunction) {
  if (!Buffer.isBuffer(value)) {
    throw new assert.AssertionError({
      message,
      actual: _typeOf(value),
      expected: 'buffer',
      operator: 'typeof ==',
      stackStartFunction
    });
  }
}

function _typeOf(value) {
  const type = typeof value;

  switch (type) {
    case 'object':
      if (value === null)
        return 'null';

      if (Array.isArray(value))
        return 'array';

      if (Buffer.isBuffer(value))
        return 'buffer';

      if (ArrayBuffer.isView(value))
        return 'arraybuffer';

      if (util.isError(value))
        return 'error';

      if (util.isDate(value))
        return 'date';

      if (util.isRegExp(value))
        return 'regexp';

      break;
    case 'number':
      if (!isFinite(value))
        return 'nan';
      break;
  }

  return type;
}

function _getConstructorName(object) {
  if (object === undefined)
    return 'undefined';

  if (object === null)
    return 'null';

  const proto = Object.getPrototypeOf(object);

  // Should never happen.
  if (proto === undefined)
    throw new Error('Bad prototype.');

  // Inherited from `null`.
  if (proto === null)
    return 'Null';

  // Someone overwrote their
  // constructor property?
  if (!proto.constructor)
    return 'Object';

  // Non-named constructor function.
  if (!proto.constructor.name)
    return 'Unknown';

  return proto.constructor.name;
}

function _getFunctionName(func) {
  return func.name || 'Unknown';
}

module.exports = assert;
