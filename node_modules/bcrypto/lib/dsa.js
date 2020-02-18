/*!
 * dsa.js - DSA for bcrypto
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

try {
  module.exports = require('./native/dsa');
} catch (e) {
  if (process.env.NODE_BACKEND === 'js')
    module.exports = require('./js/dsa');
  else
    module.exports = require('./node/dsa');
}
