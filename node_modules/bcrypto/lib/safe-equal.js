/*!
 * safe-equal.js - constant-time equals for bcrypto
 * Copyright (c) 2016-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const safe = require('./safe');

module.exports = function safeEqual(a, b) {
  return safe.safeCompare(a, b) !== 0;
};
