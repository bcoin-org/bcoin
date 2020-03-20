/*!
 * secp256k1-torsion.js - secp256k1 for bcrypto (libtorsion)
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const ECDSA = require('./ecdsa');

/*
 * Expose
 */

module.exports = new ECDSA('SECP256K1');
