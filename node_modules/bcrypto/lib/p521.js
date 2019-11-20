/*!
 * p521.js - ECDSA-P521 for bcrypto
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

try {
  module.exports = require('./native/p521');
} catch (e) {
  module.exports = require('./js/p521');
}
