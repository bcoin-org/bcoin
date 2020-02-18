/*!
 * p384.js - ECDSA-P384 for bcrypto
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

try {
  module.exports = require('./native/p384');
} catch (e) {
  module.exports = require('./js/p384');
}
