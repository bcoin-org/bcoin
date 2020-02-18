/*!
 * siphash.js - siphash for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

try {
  if (process.env.NODE_BACKEND && process.env.NODE_BACKEND !== 'native')
    throw new Error('Native backend not selected.');

  module.exports = require('loady')('bsip', __dirname);
} catch (e) {
  module.exports = require('./siphash-browser');
}
