/*!
 * hmac-drbg.js - hmac-drbg for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

if (process.env.NODE_BACKEND === 'js')
  module.exports = require('./js/hmac-drbg');
else
  module.exports = require('./native/hmac-drbg');
