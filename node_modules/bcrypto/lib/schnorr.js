/*!
 * schnorr.js - schnorr for bcrypto
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

if (process.env.NODE_BACKEND === 'js')
  module.exports = require('./js/schnorr');
else
  module.exports = require('./native/schnorr');
