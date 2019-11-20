/*!
 * blake2b.js - blake2b for bcoin
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

try {
  module.exports = require('./native/blake2b');
} catch (e) {
  if (process.env.NODE_BACKEND === 'js')
    module.exports = require('./js/blake2b');
  else
    module.exports = require('./node/blake2b');
}
