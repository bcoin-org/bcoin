/*!
 * http/index.js - http for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var utils = require('../utils');

if (!utils.isBrowser) {
  exports.request = require('./request');
  exports.client = require('./client');
  exports.wallet = require('./wallet');
  exports.base = require('./base');
  exports.server = require('./server');
}
