/*!
 * secp256k1.js - ecdsa wrapper for secp256k1 and elliptic
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var native;

if (+process.env.BCOIN_USE_ELLIPTIC !== 1) {
  try {
    native = require('secp256k1/bindings');
  } catch (e) {
    ;
  }
}

module.exports = native
  ? require('./secp256k1-native')
  : require('./secp256k1-elliptic');
