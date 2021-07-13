/*!
 * secp256k1.js - secp256k1 for bcrypto
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const binding = require('./binding');

if (binding.USE_SECP256K1 && process.env.BCRYPTO_FORCE_TORSION !== '1')
  module.exports = require('./secp256k1-libsecp256k1');
else
  module.exports = require('./secp256k1-torsion');
