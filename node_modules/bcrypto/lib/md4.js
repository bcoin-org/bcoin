/*!
 * md4.js - md4 for bcrypto
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

try {
  module.exports = require('./native/md4');
} catch (e) {
  if (process.env.NODE_BACKEND === 'js')
    module.exports = require('./js/md4');
  else
    module.exports = require('./node/md4');
}
