/*!
 * bech32.js - bech32 for bcrypto
 * Copyright (c) 2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

let BECH32;
if (process.env.NODE_BACKEND === 'js')
  BECH32 = require('../js/bech32');
else
  BECH32 = require('../native/bech32');

module.exports = new BECH32(1);
