/*!
 * md5.js - MD5 for bcrypto
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

try {
  module.exports = require('./native/md5');
} catch (e) {
  if (process.env.NODE_BACKEND === 'js')
    module.exports = require('./js/md5');
  else
    module.exports = require('./node/md5');
}
