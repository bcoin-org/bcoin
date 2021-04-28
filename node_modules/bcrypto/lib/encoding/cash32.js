/*!
 * cash32.js - cashaddr for bcrypto
 * Copyright (c) 2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

if (process.env.NODE_BACKEND === 'js')
  module.exports = require('../js/cash32');
else
  module.exports = require('../native/cash32');
