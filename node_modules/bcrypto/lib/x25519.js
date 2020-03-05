/*!
 * x25519.js - x25519 for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

if (process.env.NODE_BACKEND === 'js')
  module.exports = require('./js/x25519');
else
  module.exports = require('./native/x25519');
