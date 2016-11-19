/*!
 * ec.js - ecdsa wrapper for secp256k1 and elliptic
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var secp256k1;

if (+process.env.BCOIN_USE_ELLIPTIC !== 1) {
  try {
    secp256k1 = require('secp256k1');
  } catch (e) {
    ;
  }
}

module.exports = secp256k1
  ? require('./ec-secp256k1')
  : require('./ec-elliptic');
