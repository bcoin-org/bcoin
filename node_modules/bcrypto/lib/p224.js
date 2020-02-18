/*!
 * p224.js - ECDSA-P224 for bcrypto
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

/*
 * Expose
 */

try {
  module.exports = require('./native/p224');
} catch (e) {
  module.exports = require('./js/p224');
}
