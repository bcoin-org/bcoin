/*!
 * schnorr.js - schnorr for bcrypto
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const binding = require('./binding');

if (binding.USE_SECP256K1 && process.env.BCRYPTO_FORCE_TORSION !== '1')
  module.exports = require('./schnorr-libsecp256k1');
else
  module.exports = require('./schnorr-torsion');
