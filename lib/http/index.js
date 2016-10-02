/*!
 * http/index.js - http for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var utils = require('../utils/utils');
var lazy = require('../utils/lazy')(require, exports);

if (!utils.isBrowser) {
  lazy('request', './request');
  lazy('Client', './client');
  lazy('RPCClient', './rpcclient');
  lazy('Wallet', './wallet');
  lazy('Base', './base');
  lazy('Server', './server');
}
