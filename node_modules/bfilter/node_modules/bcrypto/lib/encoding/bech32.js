/*!
 * bech32.js - bech32 for bcrypto
 * Copyright (c) 2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

if (process.env.NODE_BACKEND === 'js')
  module.exports = require('../js/bech32');
else
  module.exports = require('../native/bech32');
