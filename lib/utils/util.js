/*!
 * util.js - utils for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');

/**
 * @exports utils/util
 */

const util = exports;

/**
 * Return hrtime (shim for browser).
 * @param {Array} time
 * @returns {Array} [seconds, nanoseconds]
 */

util.bench = function bench(time) {
  if (!process.hrtime) {
    const now = Date.now();

    if (time) {
      const [hi, lo] = time;
      const start = hi * 1000 + lo / 1e6;
      return now - start;
    }

    const ms = now % 1000;

    // Seconds
    const hi = (now - ms) / 1000;

    // Nanoseconds
    const lo = ms * 1e6;

    return [hi, lo];
  }

  if (time) {
    const [hi, lo] = process.hrtime(time);
    return hi * 1000 + lo / 1e6;
  }

  return process.hrtime();
};

/**
 * Get current time in unix time (seconds).
 * @returns {Number}
 */

util.now = function now() {
  return Math.floor(Date.now() / 1000);
};

/**
 * Get current time in unix time (milliseconds).
 * @returns {Number}
 */

util.ms = function ms() {
  return Date.now();
};

/**
 * Create a Date ISO string from time in unix time (seconds).
 * @param {Number?} time - Seconds in unix time.
 * @returns {String}
 */

util.date = function date(time) {
  if (time == null)
    time = util.now();

  return new Date(time * 1000).toISOString().slice(0, -5) + 'Z';
};

/**
 * Get unix seconds from a Date string.
 * @param {String?} date - Date ISO String.
 * @returns {Number}
 */

util.time = function time(date) {
  if (date == null)
    return util.now();

  return new Date(date) / 1000 | 0;
};

/**
 * Reverse a hex-string.
 * @param {String} str - Hex string.
 * @returns {String} Reversed hex string.
 */

util.revHex = function revHex(str) {
  assert(typeof str === 'string');
  assert((str.length & 1) === 0);

  let out = '';

  for (let i = str.length - 2; i >= 0; i -= 2)
    out += str[i] + str[i + 1];

  return out;
};
