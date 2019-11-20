/*!
 * p192.js - ECDSA-P192 for bcrypto
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

try {
  module.exports = require('./native/p192');
} catch (e) {
  module.exports = require('./js/p192');
}
