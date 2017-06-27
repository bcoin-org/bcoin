/*!
 * native.js - native bindings for bcoin
 * Copyright (c) 2016-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

exports.binding = null;

if (+process.env.BCOIN_NO_NATIVE !== 1) {
  try {
    exports.binding = require('bcoin-native');
  } catch (e) {
    ;
  }
}
