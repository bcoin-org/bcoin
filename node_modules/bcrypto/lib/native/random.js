/*!
 * random.js - random number generator for bcrypto
 * Copyright (c) 2014-2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

if (process.env.BCRYPTO_FORCE_TORSION !== '1')
  module.exports = require('./random-openssl');
else
  module.exports = require('./random-torsion');
