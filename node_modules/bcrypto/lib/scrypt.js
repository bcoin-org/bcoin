/*!
 * scrypt.js - scrypt for bcrypto
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

try {
  module.exports = require('./native/scrypt');
} catch (e) {
  if (process.env.NODE_BACKEND === 'js') {
    module.exports = require('./js/scrypt');
  } else {
    try {
      module.exports = require('./node/scrypt');
    } catch (e) {
      module.exports = require('./js/scrypt');
    }
  }
}
