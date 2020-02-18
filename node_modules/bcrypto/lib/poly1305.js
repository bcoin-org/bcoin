/*!
 * poly1305.js - poly1305 for bcrypto
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

try {
  module.exports = require('./native/poly1305');
} catch (e) {
  module.exports = require('./js/poly1305');
}
