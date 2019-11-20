/*!
 * pbkdf2.js - pbkdf2 for bcrypto
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

try {
  module.exports = require('./native/pbkdf2');
} catch (e) {
  if (process.env.NODE_BACKEND === 'js')
    module.exports = require('./js/pbkdf2');
  else
    module.exports = require('./node/pbkdf2');
}
