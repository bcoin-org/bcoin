/*!
 * aes.js - aes for bcoin
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

try {
  module.exports = require('./native/aes');
} catch (e) {
  if (process.env.NODE_BACKEND === 'js')
    module.exports = require('./js/aes');
  else
    module.exports = require('./node/aes');
}
