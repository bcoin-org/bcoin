/*!
 * secp256k1.js - secp256k1 for bcrypto
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const binding = require('./binding');

if (binding.Secp256k1 && process.env.BCRYPTO_FORCE_TORSION !== '1') {
  module.exports = require('./libsecp256k1');
} else {
  const ECDSA = require('./ecdsa');
  module.exports = new ECDSA('SECP256K1');
}
