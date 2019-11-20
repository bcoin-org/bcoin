/*!
 * aead.js - aead for bcoin
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

try {
  module.exports = require('./native/aead');
} catch (e) {
  module.exports = require('./js/aead');
}
