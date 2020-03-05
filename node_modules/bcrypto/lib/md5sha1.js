/*!
 * md5sha1.js - md5sha1 for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

if (process.env.NODE_BACKEND === 'js')
  module.exports = require('./js/md5sha1');
else
  module.exports = require('./native/md5sha1');
