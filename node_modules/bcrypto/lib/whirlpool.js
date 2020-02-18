/*!
 * whirlpool.js - whirlpool for bcrypto
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

try {
  module.exports = require('./native/whirlpool');
} catch (e) {
  if (process.env.NODE_BACKEND === 'js')
    module.exports = require('./js/whirlpool');
  else
    module.exports = require('./node/whirlpool');
}
