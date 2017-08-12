'use strict';

const _assert = require('assert');
const util = require('util');

const assert = function assert(ok, message) {
  return _assert(ok, message);
};

Object.setPrototypeOf(assert, _assert);

assert.typeOf = function typeOf(value, expected, message) {
  const type = _typeOf(value);
  if (type !== expected) {
    throw new assert.AssertionError({
      mesage: message,
      actual: type,
      expected: expected,
      operator: '===',
      stackStartFunction: typeOf
    });
  }
};

assert.notTypeOf = function notTypeOf(value, expected, message) {
  const type = _typeOf(value);
  if (type === expected) {
    throw new assert.AssertionError({
      mesage: message,
      actual: type,
      expected: expected,
      operator: '!==',
      stackStartFunction: notTypeOf
    });
  }
};

assert.instanceOf = function instanceOf(object, parent, message) {
  if (!(object instanceof parent)) {
    throw new assert.AssertionError({
      mesage: message,
      actual: _getConstructor(object),
      expected: parent.name,
      operator: '===',
      stackStartFunction: instanceOf
    });
  }
};

assert.notInstanceOf = function notInstanceOf(object, parent, message) {
  if (object instanceof parent) {
    throw new assert.AssertionError({
      mesage: message,
      actual: _getConstructor(object),
      expected: parent.name,
      operator: '!==',
      stackStartFunction: notInstanceOf
    });
  }
};

assert.isBuffer = function isBuffer(value, message) {
  if (!Buffer.isBuffer(value)) {
    throw new assert.AssertionError({
      mesage: message,
      actual: _typeOf(value),
      expected: 'buffer',
      operator: '===',
      stackStartFunction: isBuffer
    });
  }
};

assert.bufferEqual = function bufferEqual(actual, expected, message) {
  assert.isBuffer(actual, message);
  assert.isBuffer(expected, message);

  if (actual === expected)
    return;

  if (!actual.equals(expected)) {
    throw new assert.AssertionError({
      mesage: message,
      actual: actual.toString('hex'),
      expected: expected.toString('hex'),
      operator: '===',
      stackStartFunction: bufferEqual
    });
  }
};

assert.notBufferEqual = function notBufferEqual(actual, expected, message) {
  assert.isBuffer(actual, message);
  assert.isBuffer(expected, message);

  if (actual.equals(expected)) {
    throw new assert.AssertionError({
      mesage: message,
      actual: actual.toString('hex'),
      expected: expected.toString('hex'),
      operator: '!==',
      stackStartFunction: notBufferEqual
    });
  }
};

function _typeOf(value) {
  if (value === null)
    return 'null';

  if (util.isDate(value))
    return 'date';

  if (util.isRegExp(value))
    return 'regexp';

  if (util.isError(value))
    return 'error';

  if (Array.isArray(value))
    return 'array';

  if (Buffer.isBuffer(value))
    return 'buffer';

  return typeof value;
}

function _getConstructor(value) {
  if (value === undefined)
    return 'Undefined';

  if (value === null)
    return 'Null';

  const proto = Object.getPrototypeOf(value);

  if (proto == null)
    return 'Null';

  const ctor = proto.constructor;
  const name = ctor ? ctor.name : null;

  return name || 'Unknown';
}

module.exports = assert;
