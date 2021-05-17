/*!
 * enforce.js - type enforcement for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/*
 * Enforce
 */

function enforce(value, name, type) {
  if (!value) {
    const err = new TypeError(`'${name}' must be a(n) ${type}.`);

    if (Error.captureStackTrace)
      Error.captureStackTrace(err, enforce);

    throw err;
  }
}

/*
 * Expose
 */

module.exports = enforce;
