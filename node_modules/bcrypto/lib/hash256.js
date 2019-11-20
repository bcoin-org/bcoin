/*!
 * hash256.js - hash256 for bcrypto
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

try {
  module.exports = require('./native/hash256');
} catch (e) {
  if (process.env.NODE_BACKEND === 'js')
    module.exports = require('./js/hash256');
  else
    module.exports = require('./node/hash256');
}
