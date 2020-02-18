/*!
 * blake2s.js - blake2s for bcoin
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

try {
  module.exports = require('./native/blake2s');
} catch (e) {
  if (process.env.NODE_BACKEND === 'js')
    module.exports = require('./js/blake2s');
  else
    module.exports = require('./node/blake2s');
}
