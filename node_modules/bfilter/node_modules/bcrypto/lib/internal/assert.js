/*!
 * assert.js - assert for bcrypto
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

/*
 * Assert
 */

function assert(val, msg) {
  if (!val) {
    const err = new Error(msg || 'Assertion failed');

    if (Error.captureStackTrace)
      Error.captureStackTrace(err, assert);

    throw err;
  }
}

/*
 * Expose
 */

module.exports = assert;
