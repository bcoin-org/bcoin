/*!
 * native.js - native bindings for bcoin
 * Copyright (c) 2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var isBrowser =
  (typeof process !== 'undefined' && process.browser)
  || typeof window !== 'undefined';

module.exports = null;

if (!isBrowser && +process.env.BCOIN_NO_NATIVE !== 1) {
  try {
    module.exports = require('bcoin-native');
  } catch (e) {
    ;
  }
}
