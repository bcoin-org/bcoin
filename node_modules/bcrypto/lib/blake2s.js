/*!
 * blake2s.js - blake2s for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

if (process.env.NODE_BACKEND === 'js')
  module.exports = require('./js/blake2s');
else
  module.exports = require('./native/blake2s');
