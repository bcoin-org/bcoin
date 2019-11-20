/*!
 * random.js - random for bcrypto
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

try {
  module.exports = require('./native/random');
} catch (e) {
  if (process.env.NODE_BACKEND === 'js' && process.env.NODE_TEST === '1')
    module.exports = require('./js/random');
  else
    module.exports = require('./node/random');
}
