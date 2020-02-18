/*!
 * p256.js - ECDSA-P256 for bcrypto
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

try {
  module.exports = require('./native/p256');
} catch (e) {
  module.exports = require('./js/p256');
}
