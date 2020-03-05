/*!
 * poly1305.js - poly1305 for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

if (process.env.NODE_BACKEND === 'js')
  module.exports = require('./js/poly1305');
else
  module.exports = require('./native/poly1305');
