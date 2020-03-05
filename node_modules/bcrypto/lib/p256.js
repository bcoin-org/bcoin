/*!
 * p256.js - ECDSA-P256 for bcrypto
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

if (process.env.NODE_BACKEND === 'js')
  module.exports = require('./js/p256');
else
  module.exports = require('./native/p256');
