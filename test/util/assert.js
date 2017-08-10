'use strict';

const _assert = require('assert');
const util = require('util');

const assert = function assert(ok, message) {
  return _assert(ok, message);
};

Object.setPrototypeOf(assert, _assert);

assert.isBuffer = function isBuffer(value, message) {
  if (!Buffer.isBuffer(value)) {
    throw new assert.AssertionError({
      mesage: message,
      actual: typeOf(value),
      expected: 'buffer',
      operator: '===',
      stackStartFunction: isBuffer
    });
  }
};

assert.bufferEqual = function bufferEqual(actual, expected, message) {
  assert.isBuffer(actual, message);
  assert.isBuffer(expected, message);

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

function typeOf(value) {
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

module.exports = assert;
