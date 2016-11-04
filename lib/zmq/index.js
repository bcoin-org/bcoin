/*!
 * zmq/index.js - zmq for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var utils = require('../utils/utils');

if (!utils.isBrowser) {
  exports.sockets = require('./sockets');
}
